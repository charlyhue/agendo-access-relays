//! `POST /v1/push` : vérifications dans l'ordre, puis remise à APNs ou FCM.
//!
//! 1. place libre (sinon 503), corps ≤ `max_body` (sinon 413) ;
//! 2. jeton push (`Authorization: Bearer`) vérifié avec les clés de confiance (sinon 401) ;
//! 3. `Agendo-Signature` vérifiée avec la clé `house_key` du jeton, sur la maison, la méthode,
//!    le chemin et la requête de la ligne de requête, l'heure et le corps ; la maison qu'elle
//!    nomme (`house`) doit être celle du jeton (`sub`) (sinon 401) ;
//! 4. corps JSON lu et validé (`PushRequest::validate`, sinon 400), plateforme servie par ce
//!    relais (sinon 400) ;
//! 5. quotas du jeton (sinon 429) ;
//! 6. remise : `sent` et `unregistered` en 200, `rejected` par APNs/FCM en 422, panne passagère
//!    d'APNs/FCM (5xx, 429, délai dépassé) en 502 `unavailable`.
//!
//! `unavailable` (502, ou 503 si le relais est surchargé) est le seul statut passager
//! (`PushStatus::is_temporary`) : la maison réessaie plus tard, ou auprès d'un autre relais push.
//! `rejected` et `quota` sont définitifs.
//!
//! Réponse toujours en JSON : `{ "status": "sent" | "unregistered" | "rejected" | "quota" | "unavailable", "detail"? }`.
//! Le journal ne contient ni jeton, ni signature, ni jeton de téléphone, ni chiffré.

use std::{sync::Arc, time::Instant};

use agendo_access_protocol::{
    keys::TrustedKeys,
    push::{PUSH_PATH, Platform, PushRequest, PushResponse, PushStatus},
    signature::{SIGNATURE_HEADER, verify_request},
    token::PushClaims,
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use tokio::sync::Semaphore;

use crate::{
    apns::ApnsClient,
    config::PushLimits,
    delivery::{Delivery, UpstreamError},
    fcm::FcmClient,
    metrics::PushMetrics,
    quotas::QuotaBook,
};

/// État partagé du relais push.
#[derive(Debug)]
pub struct PushState {
    pub keys: TrustedKeys,
    pub quotas: QuotaBook,
    pub apns: Option<ApnsClient>,
    pub fcm: Option<FcmClient>,
    pub metrics: PushMetrics,
    pub limits: PushLimits,
    slots: Semaphore,
}

impl PushState {
    pub fn new(keys: TrustedKeys, apns: Option<ApnsClient>, fcm: Option<FcmClient>, limits: PushLimits) -> Self {
        Self {
            keys,
            quotas: QuotaBook::new(limits.max_houses),
            apns,
            fcm,
            metrics: PushMetrics::new(),
            slots: Semaphore::new(limits.max_concurrent),
            limits,
        }
    }
}

/// Routes du relais push.
pub fn router(state: Arc<PushState>) -> Router {
    Router::new().route(PUSH_PATH, post(push)).with_state(state)
}

/// Refus avant toute remise : code HTTP, statut et détail pour la maison.
struct Refusal(StatusCode, PushStatus, String);

impl Refusal {
    fn rejected(code: StatusCode, detail: impl Into<String>) -> Self {
        Self(code, PushStatus::Rejected, detail.into())
    }
}

async fn push(State(state): State<Arc<PushState>>, request: Request) -> Response {
    let started = Instant::now();
    let Ok(_slot) = state.slots.try_acquire() else {
        state.metrics.unavailable.inc();
        return answer(StatusCode::SERVICE_UNAVAILABLE, PushStatus::Unavailable, Some("relais surchargé, réessayer".into()));
    };
    let (claims, push) = match check(&state, request).await {
        Ok(checked) => checked,
        Err(Refusal(code, status, detail)) => {
            match status {
                PushStatus::Quota => state.metrics.quota.inc(),
                _ => state.metrics.rejected.inc(),
            }
            tracing::debug!(code = code.as_u16(), raison = %detail, "notification refusée");
            return answer(code, status, Some(detail));
        }
    };
    let now = relay_common::time::now_unix();
    let timeout = state.limits.upstream_timeout;
    let outcome = match (push.platform, &state.apns, &state.fcm) {
        (Platform::Ios, Some(apns), _) => apns.send(&push, now, timeout).await,
        (Platform::Android, _, Some(fcm)) => fcm.send(&push, now, timeout).await,
        // Écarté par `check`.
        _ => Ok(Delivery::Rejected("plateforme non prise en charge".into())),
    };
    let platform = match push.platform {
        Platform::Ios => "ios",
        Platform::Android => "android",
    };
    let (code, status, detail) = match outcome {
        Ok(Delivery::Sent) => (StatusCode::OK, PushStatus::Sent, None),
        Ok(Delivery::Unregistered) => (StatusCode::OK, PushStatus::Unregistered, None),
        Ok(Delivery::Rejected(reason)) => (StatusCode::UNPROCESSABLE_ENTITY, PushStatus::Rejected, Some(reason)),
        Err(UpstreamError::Unavailable(reason)) => {
            match push.platform {
                Platform::Ios => state.metrics.upstream_ios.inc(),
                Platform::Android => state.metrics.upstream_android.inc(),
            }
            tracing::warn!(maison = %claims.sub, plateforme = platform, raison = %reason, "service de notifications en erreur");
            (StatusCode::BAD_GATEWAY, PushStatus::Unavailable, Some("service de notifications indisponible, réessayer".into()))
        }
    };
    match status {
        PushStatus::Sent => state.metrics.sent.inc(),
        PushStatus::Unregistered => state.metrics.unregistered.inc(),
        PushStatus::Rejected => state.metrics.rejected.inc(),
        PushStatus::Quota => state.metrics.quota.inc(),
        PushStatus::Unavailable => state.metrics.unavailable.inc(),
    }
    tracing::info!(
        maison = %claims.sub,
        plateforme = platform,
        niveau = push.level.as_str(),
        statut = ?status,
        duree_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "notification traitée"
    );
    answer(code, status, detail)
}

/// Étapes 1 à 5 : rend le jeton vérifié et la requête validée, ou le refus.
async fn check(state: &PushState, request: Request) -> Result<(PushClaims, PushRequest), Refusal> {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, state.limits.max_body)
        .await
        .map_err(|_| Refusal::rejected(StatusCode::PAYLOAD_TOO_LARGE, "corps trop long"))?;
    let now = relay_common::time::now_unix();
    let token = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .ok_or_else(|| Refusal::rejected(StatusCode::UNAUTHORIZED, "jeton push absent"))?;
    let claims = PushClaims::verify(token.trim(), &state.keys, now)
        .map_err(|e| Refusal::rejected(StatusCode::UNAUTHORIZED, format!("jeton push refusé : {e}")))?;
    let house_key = claims.house_key().map_err(|_| Refusal::rejected(StatusCode::UNAUTHORIZED, "clé de la maison invalide"))?;
    let signature = parts
        .headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Refusal::rejected(StatusCode::UNAUTHORIZED, "en-tête Agendo-Signature absent"))?;
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or(parts.uri.path());
    let signed = verify_request(signature, parts.method.as_str(), path, &body, now, &house_key)
        .map_err(|e| Refusal::rejected(StatusCode::UNAUTHORIZED, format!("signature refusée : {e}")))?;
    if signed.house != claims.sub {
        return Err(Refusal::rejected(StatusCode::UNAUTHORIZED, "signature d'une autre maison que celle du jeton push"));
    }
    let push: PushRequest = serde_json::from_slice(&body).map_err(|_| Refusal::rejected(StatusCode::BAD_REQUEST, "corps JSON invalide"))?;
    push.validate().map_err(|e| Refusal::rejected(StatusCode::BAD_REQUEST, e.to_string()))?;
    let served = match push.platform {
        Platform::Ios => state.apns.is_some(),
        Platform::Android => state.fcm.is_some(),
    };
    if !served {
        return Err(Refusal::rejected(StatusCode::BAD_REQUEST, "plateforme non prise en charge par ce relais"));
    }
    state
        .quotas
        .check(&claims.sub, claims.quotas, push.level, now)
        .map_err(|e| Refusal(StatusCode::TOO_MANY_REQUESTS, PushStatus::Quota, e.to_string()))?;
    Ok((claims, push))
}

/// Réponse JSON.
fn answer(code: StatusCode, status: PushStatus, detail: Option<String>) -> Response {
    (code, Json(PushResponse { status, detail })).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use agendo_access_protocol::{
        SigningKey,
        keys::{TrustedKey, encode_public_key},
        push::PushLevel,
        signature::sign_request,
        token::Quotas,
    };
    use axum::http::StatusCode as S;
    use serde_json::Value;

    use super::*;
    use crate::{apns, fcm};

    fn plane() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn house() -> SigningKey {
        SigningKey::from_bytes(&[2; 32])
    }

    fn keys() -> TrustedKeys {
        TrustedKeys::new(vec![TrustedKey { kid: "k1".into(), key: encode_public_key(&plane().verifying_key()) }]).unwrap()
    }

    fn now() -> i64 {
        relay_common::time::now_unix()
    }

    fn push_token(quotas: Quotas, lifetime: i64) -> String {
        PushClaims {
            iss: "https://api.exemple.fr".into(),
            sub: HOUSE.into(),
            house_key: encode_public_key(&house().verifying_key()),
            iat: now() - 10,
            exp: now() + lifetime,
            quotas,
        }
        .sign("k1", &plane())
    }

    const Q: Quotas = Quotas { per_hour: 100, critical_per_day: 10 };
    /// `sub` du jeton push, que la signature doit nommer.
    const HOUSE: &str = "maison-1";

    struct Relay {
        addr: SocketAddr,
        state: Arc<PushState>,
        apns_seen: tokio::sync::mpsc::UnboundedReceiver<apns::tests::Seen>,
        fcm_seen: tokio::sync::mpsc::UnboundedReceiver<(String, axum::http::HeaderMap, Value)>,
    }

    async fn start_with(apns_status: S, apns_body: &'static str, limits: PushLimits) -> Relay {
        let (apns_url, apns_seen) = apns::tests::fake_apns(apns_status, apns_body).await;
        let (fcm_url, _fake, fcm_seen) = fcm::tests::fake_fcm(S::OK, "{}").await;
        let state = Arc::new(PushState::new(keys(), Some(apns::tests::client(apns_url)), Some(fcm::tests::client(&fcm_url)), limits));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Relay { addr, state, apns_seen, fcm_seen }
    }

    async fn start() -> Relay {
        start_with(S::OK, "", PushLimits::default()).await
    }

    fn body(request: &PushRequest) -> Vec<u8> {
        serde_json::to_vec(request).unwrap()
    }

    /// Envoie `body` avec le jeton et la signature donnés ; rend le code et la réponse.
    async fn post(relay: &Relay, path: &str, token: Option<&str>, signature: Option<String>, body: Vec<u8>) -> (S, PushResponse) {
        let mut req = reqwest::Client::new().post(format!("http://{}{path}", relay.addr)).body(body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        if let Some(signature) = signature {
            req = req.header(SIGNATURE_HEADER, signature);
        }
        let response = req.send().await.unwrap();
        let code = response.status();
        (code, response.json().await.unwrap())
    }

    async fn send(relay: &Relay, request: &PushRequest) -> (S, PushResponse) {
        let b = body(request);
        let sig = sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now());
        post(relay, "/v1/push", Some(&push_token(Q, 3600)), Some(sig), b).await
    }

    #[tokio::test]
    async fn ios_and_android_are_delivered() {
        let mut relay = start().await;
        let (code, r) = send(&relay, &apns::tests::request(PushLevel::TimeSensitive)).await;
        assert_eq!((code, r.status), (S::OK, PushStatus::Sent));
        assert_eq!(relay.apns_seen.recv().await.unwrap().body, apns::payload(&apns::tests::request(PushLevel::TimeSensitive)));
        let (code, r) = send(&relay, &fcm::tests::request(PushLevel::Active)).await;
        assert_eq!((code, r.status), (S::OK, PushStatus::Sent));
        assert_eq!(relay.fcm_seen.recv().await.unwrap().2, fcm::message(&fcm::tests::request(PushLevel::Active)));
        assert_eq!(relay.state.metrics.sent.get(), 2);
    }

    #[tokio::test]
    async fn unregistered_and_rejected_from_apns() {
        let relay = start_with(S::GONE, r#"{"reason":"Unregistered"}"#, PushLimits::default()).await;
        let (code, r) = send(&relay, &apns::tests::request(PushLevel::Active)).await;
        assert_eq!((code, r.status), (S::OK, PushStatus::Unregistered));
        let relay = start_with(S::BAD_REQUEST, r#"{"reason":"BadDeviceToken"}"#, PushLimits::default()).await;
        let (code, r) = send(&relay, &apns::tests::request(PushLevel::Active)).await;
        assert_eq!((code, r.status, r.detail.as_deref()), (S::UNPROCESSABLE_ENTITY, PushStatus::Rejected, Some("BadDeviceToken")));
    }

    #[tokio::test]
    async fn upstream_failure_is_unavailable_and_temporary() {
        let relay = start_with(S::SERVICE_UNAVAILABLE, "{}", PushLimits::default()).await;
        let (code, r) = send(&relay, &apns::tests::request(PushLevel::Active)).await;
        assert_eq!((code, r.status), (S::BAD_GATEWAY, PushStatus::Unavailable));
        assert!(r.status.is_temporary());
        assert_eq!(relay.state.metrics.unavailable.get(), 1);
        assert_eq!(relay.state.metrics.upstream_ios.get(), 1);
        let relay = start_with(S::TOO_MANY_REQUESTS, r#"{"reason":"TooManyRequests"}"#, PushLimits::default()).await;
        assert_eq!(send(&relay, &apns::tests::request(PushLevel::Active)).await.1.status, PushStatus::Unavailable);
    }

    #[tokio::test]
    async fn signature_must_name_the_house_of_the_token() {
        let relay = start().await;
        let token = push_token(Q, 3600);
        let b = body(&apns::tests::request(PushLevel::Active));
        // Bonne clé, mais la signature nomme une autre maison que le `sub` du jeton.
        let other = sign_request(&house(), "maison-2", "POST", "/v1/push", &b, now());
        let (code, r) = post(&relay, "/v1/push", Some(&token), Some(other), b.clone()).await;
        assert_eq!((code, r.status), (S::UNAUTHORIZED, PushStatus::Rejected));
        // Ancienne forme, sans `house` : refusée.
        let old = sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now()).replace("house=maison-1,", "");
        assert_eq!(post(&relay, "/v1/push", Some(&token), Some(old), b).await.0, S::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ios_token_must_be_lowercase_hex() {
        let relay = start().await;
        let upper = PushRequest { device: apns::tests::request(PushLevel::Active).device.to_uppercase(), ..apns::tests::request(PushLevel::Active) };
        let (code, r) = send(&relay, &upper).await;
        assert_eq!((code, r.status), (S::BAD_REQUEST, PushStatus::Rejected));
    }

    #[tokio::test]
    async fn token_is_required_and_checked() {
        let relay = start().await;
        let b = body(&apns::tests::request(PushLevel::Active));
        let sig = || Some(sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now()));
        let (code, r) = post(&relay, "/v1/push", None, sig(), b.clone()).await;
        assert_eq!((code, r.status), (S::UNAUTHORIZED, PushStatus::Rejected));
        let (code, _) = post(&relay, "/v1/push", Some(&push_token(Q, -1)), sig(), b.clone()).await;
        assert_eq!(code, S::UNAUTHORIZED, "jeton expiré");
        let tunnel = agendo_access_protocol::token::TunnelClaims {
            iss: "x".into(),
            sub: "maison-1".into(),
            host: "abcdefghijklmnop.maisons.exemple.fr".into(),
            house_key: encode_public_key(&house().verifying_key()),
            iat: now(),
            exp: now() + 60,
        }
        .sign("k1", &plane());
        let (code, _) = post(&relay, "/v1/push", Some(&tunnel), sig(), b).await;
        assert_eq!(code, S::UNAUTHORIZED, "jeton de tunnel refusé");
    }

    #[tokio::test]
    async fn signature_is_required_and_checked() {
        let relay = start().await;
        let token = push_token(Q, 3600);
        let b = body(&apns::tests::request(PushLevel::Active));
        let (code, _) = post(&relay, "/v1/push", Some(&token), None, b.clone()).await;
        assert_eq!(code, S::UNAUTHORIZED, "sans signature");
        let other_body = sign_request(&house(), HOUSE, "POST", "/v1/push", b"{}", now());
        assert_eq!(post(&relay, "/v1/push", Some(&token), Some(other_body), b.clone()).await.0, S::UNAUTHORIZED);
        let stale = sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now() - 120);
        assert_eq!(post(&relay, "/v1/push", Some(&token), Some(stale), b.clone()).await.0, S::UNAUTHORIZED);
        let other_key = sign_request(&SigningKey::from_bytes(&[3; 32]), HOUSE, "POST", "/v1/push", &b, now());
        assert_eq!(post(&relay, "/v1/push", Some(&token), Some(other_key), b.clone()).await.0, S::UNAUTHORIZED);
        // La requête `?…` fait partie du chemin signé.
        let with_query = sign_request(&house(), HOUSE, "POST", "/v1/push?essai=1", &b, now());
        assert_eq!(post(&relay, "/v1/push?essai=1", Some(&token), Some(with_query), b.clone()).await.0, S::OK);
        let without_query = sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now());
        assert_eq!(post(&relay, "/v1/push?essai=1", Some(&token), Some(without_query), b).await.0, S::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_bodies_are_rejected() {
        let relay = start_with(S::OK, "", PushLimits { max_body: 4096, ..PushLimits::default() }).await;
        let token = push_token(Q, 3600);
        let signed = |b: &[u8]| Some(sign_request(&house(), HOUSE, "POST", "/v1/push", b, now()));
        let (code, r) = post(&relay, "/v1/push", Some(&token), signed(b"pas du json"), b"pas du json".to_vec()).await;
        assert_eq!((code, r.status), (S::BAD_REQUEST, PushStatus::Rejected));
        let long = body(&PushRequest { collapse_id: Some("x".repeat(65)), ..apns::tests::request(PushLevel::Active) });
        assert_eq!(post(&relay, "/v1/push", Some(&token), signed(&long), long.clone()).await.0, S::BAD_REQUEST);
        let huge = vec![b' '; 5000];
        assert_eq!(post(&relay, "/v1/push", Some(&token), signed(&huge), huge.clone()).await.0, S::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn quotas_are_applied() {
        let relay = start().await;
        let token = push_token(Quotas { per_hour: 1, critical_per_day: 0 }, 3600);
        let b = body(&apns::tests::request(PushLevel::Critical));
        let (code, r) = post(&relay, "/v1/push", Some(&token), Some(sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now())), b).await;
        assert_eq!((code, r.status), (S::TOO_MANY_REQUESTS, PushStatus::Quota));
        let b = body(&apns::tests::request(PushLevel::Active));
        let sig = || Some(sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now()));
        assert_eq!(post(&relay, "/v1/push", Some(&token), sig(), b.clone()).await.1.status, PushStatus::Sent);
        assert_eq!(post(&relay, "/v1/push", Some(&token), sig(), b.clone()).await.1.status, PushStatus::Quota);
        assert_eq!(relay.state.metrics.quota.get(), 2);
    }

    #[tokio::test]
    async fn platform_not_configured() {
        let state = Arc::new(PushState::new(keys(), None, None, PushLimits::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (apns_seen, fcm_seen) = (tokio::sync::mpsc::unbounded_channel().1, tokio::sync::mpsc::unbounded_channel().1);
        let relay = Relay { addr, state, apns_seen, fcm_seen };
        let (code, r) = send(&relay, &apns::tests::request(PushLevel::Active)).await;
        assert_eq!((code, r.status), (S::BAD_REQUEST, PushStatus::Rejected));
    }

    /// Écrit les logs dans un tampon partagé.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Abonné global (un seul par processus) : tous les tests du binaire écrivent dans le
    /// même tampon, et aucun ne doit y laisser de secret.
    fn capture() -> &'static Capture {
        static CAPTURE: std::sync::OnceLock<Capture> = std::sync::OnceLock::new();
        CAPTURE.get_or_init(|| {
            let capture = Capture::default();
            let writer = capture.clone();
            let subscriber = tracing_subscriber::fmt().json().with_max_level(tracing::Level::DEBUG).with_writer(move || writer.clone()).finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            capture
        })
    }

    #[tokio::test]
    async fn logs_hold_no_secret_nor_content() {
        let capture = capture();
        let relay = start().await;
        let request = apns::tests::request(PushLevel::Active);
        let token = push_token(Q, 3600);
        let b = body(&request);
        let sig = sign_request(&house(), HOUSE, "POST", "/v1/push", &b, now());
        assert_eq!(post(&relay, "/v1/push", Some(&token), Some(sig.clone()), b.clone()).await.0, S::OK);
        assert_eq!(post(&relay, "/v1/push", Some(&token), None, b).await.0, S::UNAUTHORIZED);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("maison-1"), "la maison est nommée : {logs}");
        for secret in [token.as_str(), &sig, &request.device, &request.ciphertext, "sonnette-entree"] {
            assert!(!logs.contains(secret), "{secret:?} dans les logs : {logs}");
        }
    }
}
