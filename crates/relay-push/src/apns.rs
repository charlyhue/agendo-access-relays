//! Client APNs : HTTP/2, authentification par jeton (clé `.p8`, JWT ES256 mis en cache).
//!
//! La notification part avec une alerte générique en clair ([`GENERIC_ALERT`]),
//! `mutable-content: 1` pour que l'extension du téléphone la déchiffre, l'`interruption-level`
//! demandé et l'enveloppe chiffrée sous la clé [`APNS_PAYLOAD_KEY`]. Le relais n'en lit rien.

use std::{
    sync::{Mutex, PoisonError},
    time::Duration,
};

use agendo_access_protocol::{
    b64,
    push::{APNS_PAYLOAD_KEY, GENERIC_ALERT, PushLevel, PushRequest},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};

use crate::delivery::{Delivery, UpstreamError};

/// URL d'APNs en production.
pub const PRODUCTION_URL: &str = "https://api.push.apple.com";
/// URL d'APNs en développement (applications signées pour le développement).
pub const SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";
/// Durée de réutilisation du jeton fournisseur (Apple : entre 20 et 60 minutes).
pub const PROVIDER_TOKEN_TTL_SECS: i64 = 40 * 60;

/// Configuration APNs. La clé vient d'un fichier monté (`.p8`), jamais d'une variable.
pub struct ApnsConfig {
    pub key: SigningKey,
    /// Identifiant de la clé (10 caractères, console Apple).
    pub key_id: String,
    /// Identifiant de l'équipe Apple.
    pub team_id: String,
    /// Identifiant de l'app (`apns-topic`).
    pub topic: String,
    /// `PRODUCTION_URL`, `SANDBOX_URL`, ou un faux APNs en test.
    pub base_url: String,
}

impl std::fmt::Debug for ApnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Jamais la clé.
        f.debug_struct("ApnsConfig")
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .field("topic", &self.topic)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Erreur de lecture de la clé `.p8`.
#[derive(Debug, thiserror::Error)]
#[error("clé APNs illisible (PKCS#8 PEM P-256 attendu)")]
pub struct KeyError;

/// Relit une clé `.p8` (PKCS#8 PEM, courbe P-256).
pub fn parse_p8(pem: &str) -> Result<SigningKey, KeyError> {
    use p256::pkcs8::DecodePrivateKey;
    SigningKey::from_pkcs8_pem(pem.trim()).map_err(|_| KeyError)
}

/// Client APNs.
#[derive(Debug)]
pub struct ApnsClient {
    config: ApnsConfig,
    http: reqwest::Client,
    token: Mutex<Option<(String, i64)>>,
}

/// Jeton de téléphone APNs admis dans l'URL (`push::is_apns_token` du protocole : hexadécimal
/// minuscule, longueur paire, 64 caractères au moins). `PushRequest::validate` l'a déjà vérifié ;
/// le client le revérifie avant de l'écrire dans le chemin de la requête.
pub fn valid_device_token(token: &str) -> bool {
    agendo_access_protocol::push::is_apns_token(token)
}

/// Corps JSON envoyé à APNs.
pub fn payload(request: &PushRequest) -> Value {
    let mut aps = json!({
        "alert": { "body": GENERIC_ALERT },
        "mutable-content": 1,
        "interruption-level": request.level.as_str(),
    });
    let sound = match request.level {
        PushLevel::Passive => None,
        PushLevel::Active | PushLevel::TimeSensitive => Some(json!("default")),
        PushLevel::Critical => Some(json!({ "critical": 1, "name": "default", "volume": 1.0 })),
    };
    if let (Some(sound), Some(aps)) = (sound, aps.as_object_mut()) {
        aps.insert("sound".into(), sound);
    }
    json!({
        "aps": aps,
        APNS_PAYLOAD_KEY: { "key_id": request.key_id, "ciphertext": request.ciphertext },
    })
}

/// Raison rendue par APNs (`{"reason": "BadDeviceToken"}`), réduite à des caractères sûrs.
fn reason(body: &[u8]) -> String {
    let reason = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default();
    let clean: String = reason.chars().filter(char::is_ascii_alphanumeric).take(64).collect();
    if clean.is_empty() { "inconnue".into() } else { clean }
}

impl ApnsClient {
    pub fn new(config: ApnsConfig, http: reqwest::Client) -> Self {
        Self { config, http, token: Mutex::new(None) }
    }

    /// Jeton fournisseur (JWT ES256), réutilisé pendant [`PROVIDER_TOKEN_TTL_SECS`].
    pub fn provider_token(&self, now: i64) -> String {
        let mut cached = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((token, iat)) = cached.as_ref()
            && (0..PROVIDER_TOKEN_TTL_SECS).contains(&(now - iat))
        {
            return token.clone();
        }
        let header = json!({ "alg": "ES256", "kid": self.config.key_id });
        let claims = json!({ "iss": self.config.team_id, "iat": now });
        let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let signature: Signature = self.config.key.sign(input.as_bytes());
        let token = format!("{input}.{}", b64(&signature.to_bytes()));
        *cached = Some((token.clone(), now));
        token
    }

    fn forget_provider_token(&self) {
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Envoie à APNs.
    pub async fn send(&self, request: &PushRequest, now: i64, timeout: Duration) -> Result<Delivery, UpstreamError> {
        if !valid_device_token(&request.device) {
            return Ok(Delivery::Rejected("jeton de téléphone iOS invalide".into()));
        }
        let url = format!("{}/3/device/{}", self.config.base_url.trim_end_matches('/'), request.device);
        let priority = if request.level == PushLevel::Passive { "5" } else { "10" };
        let mut builder = self
            .http
            .post(url)
            .timeout(timeout)
            .header("authorization", format!("bearer {}", self.provider_token(now)))
            .header("apns-topic", &self.config.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", priority)
            .json(&payload(request));
        if let Some(collapse) = &request.collapse_id {
            builder = builder.header("apns-collapse-id", collapse);
        }
        // `without_url` : l'URL porte le jeton du téléphone, qui ne doit pas finir au journal.
        let response = builder.send().await.map_err(|e| UpstreamError::Unavailable(format!("APNs : {}", e.without_url())))?;
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        match status.as_u16() {
            200 => Ok(Delivery::Sent),
            410 => Ok(Delivery::Unregistered),
            403 => {
                let reason = reason(&body);
                if reason.ends_with("ProviderToken") {
                    self.forget_provider_token();
                }
                Err(UpstreamError::Unavailable(format!("APNs {status} {reason}")))
            }
            429 | 500..=599 => Err(UpstreamError::Unavailable(format!("APNs {status} {}", reason(&body)))),
            _ => Ok(Delivery::Rejected(reason(&body))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use std::sync::Arc;

    use agendo_access_protocol::{push::Platform, unb64};
    use axum::{
        Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode, Version},
        routing::post,
    };
    use p256::{
        ecdsa::{VerifyingKey, signature::Verifier},
        pkcs8::{EncodePrivateKey, LineEnding},
    };
    use tokio::sync::mpsc;

    use super::*;

    pub(crate) fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
    }

    /// Chiffré réel (nonce fixe) d'une notification de test.
    pub(crate) fn ciphertext() -> String {
        let clear = agendo_access_protocol::push::PushPlaintext {
            title: "Sonnette".into(),
            body: "Quelqu'un sonne".into(),
            category: None,
            thread: None,
            data: Default::default(),
            sent_at: 1_793_000_000,
        };
        agendo_access_protocol::push::seal_with_nonce(&[1; 32], "cle-1", &clear, [3; 24]).unwrap()
    }

    pub(crate) fn request(level: PushLevel) -> PushRequest {
        PushRequest {
            device: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".into(),
            platform: Platform::Ios,
            level,
            collapse_id: Some("sonnette-entree".into()),
            key_id: "cle-1".into(),
            ciphertext: ciphertext(),
        }
    }

    /// Requête reçue par le faux APNs.
    #[derive(Debug)]
    pub(crate) struct Seen {
        pub version: Version,
        pub device: String,
        pub headers: HeaderMap,
        pub body: Value,
    }

    /// Faux APNs (HTTP/2 en clair) qui répond `status` et `body` ; rend son URL et les requêtes vues.
    pub(crate) async fn fake_apns(status: StatusCode, body: &'static str) -> (String, mpsc::UnboundedReceiver<Seen>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/3/device/{device}",
            post(move |State(tx): State<Arc<mpsc::UnboundedSender<Seen>>>, Path(device): Path<String>, req: axum::extract::Request| async move {
                let version = req.version();
                let headers = req.headers().clone();
                let bytes = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
                tx.send(Seen { version, device, headers, body: serde_json::from_slice(&bytes).unwrap() }).unwrap();
                (status, body)
            }),
        );
        let app = app.with_state(Arc::new(tx));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, rx)
    }

    pub(crate) fn h2c_client() -> reqwest::Client {
        reqwest::Client::builder().http2_prior_knowledge().build().unwrap()
    }

    pub(crate) fn client(base_url: String) -> ApnsClient {
        ApnsClient::new(
            ApnsConfig { key: test_key(), key_id: "KEYID12345".into(), team_id: "TEAM123456".into(), topic: "fr.exemple.agendo".into(), base_url },
            h2c_client(),
        )
    }

    const NOW: i64 = 1_793_000_000;
    const T: Duration = Duration::from_secs(5);

    #[test]
    fn p8_round_trip_and_garbage() {
        let pem = test_key().to_pkcs8_pem(LineEnding::LF).unwrap();
        assert_eq!(parse_p8(&pem).unwrap(), test_key());
        assert!(parse_p8("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err());
        assert!(parse_p8("").is_err());
    }

    #[test]
    fn device_token_must_be_hex() {
        assert!(valid_device_token(&request(PushLevel::Active).device));
        let upper = request(PushLevel::Active).device.to_uppercase();
        for bad in ["", "abc", "../../3/device/x", "a1b2?x=1", "a1b2#", "A1B2zz", &"a".repeat(201), &"ab".repeat(16), &upper] {
            assert!(!valid_device_token(bad), "{bad:?}");
        }
    }

    #[test]
    fn payload_per_level() {
        let p = payload(&request(PushLevel::TimeSensitive));
        assert_eq!(
            p,
            json!({
                "aps": {
                    "alert": { "body": GENERIC_ALERT },
                    "mutable-content": 1,
                    "interruption-level": "time-sensitive",
                    "sound": "default",
                },
                "agendo": { "key_id": "cle-1", "ciphertext": ciphertext() },
            })
        );
        assert_eq!(payload(&request(PushLevel::Critical))["aps"]["sound"], json!({ "critical": 1, "name": "default", "volume": 1.0 }));
        assert!(payload(&request(PushLevel::Passive))["aps"].get("sound").is_none(), "passive : sans son");
        assert_eq!(payload(&request(PushLevel::Active))["aps"]["interruption-level"], "active");
    }

    #[test]
    fn provider_token_is_a_valid_es256_jwt_and_is_cached() {
        let c = client("http://inutile".into());
        let token = c.provider_token(NOW);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(&unb64(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "ES256", "kid": "KEYID12345" }));
        let claims: Value = serde_json::from_slice(&unb64(parts[1]).unwrap()).unwrap();
        assert_eq!(claims, json!({ "iss": "TEAM123456", "iat": NOW }));
        let signature = Signature::from_slice(&unb64(parts[2]).unwrap()).unwrap();
        VerifyingKey::from(&test_key()).verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature).unwrap();
        assert_eq!(c.provider_token(NOW + PROVIDER_TOKEN_TTL_SECS - 1), token, "réutilisé");
        assert_ne!(c.provider_token(NOW + PROVIDER_TOKEN_TTL_SECS), token, "renouvelé");
    }

    #[tokio::test]
    async fn sends_http2_request_with_apns_headers() {
        let (url, mut seen) = fake_apns(StatusCode::OK, "").await;
        let c = client(url);
        assert_eq!(c.send(&request(PushLevel::TimeSensitive), NOW, T).await.unwrap(), Delivery::Sent);
        let s = seen.recv().await.unwrap();
        assert_eq!(s.version, Version::HTTP_2);
        assert_eq!(s.device, request(PushLevel::Active).device);
        let h = |name: &str| s.headers.get(name).map(|v| v.to_str().unwrap().to_owned());
        assert_eq!(h("authorization"), Some(format!("bearer {}", c.provider_token(NOW))));
        assert_eq!(h("apns-topic").as_deref(), Some("fr.exemple.agendo"));
        assert_eq!(h("apns-push-type").as_deref(), Some("alert"));
        assert_eq!(h("apns-priority").as_deref(), Some("10"));
        assert_eq!(h("apns-collapse-id").as_deref(), Some("sonnette-entree"));
        assert_eq!(s.body, payload(&request(PushLevel::TimeSensitive)));

        assert_eq!(c.send(&PushRequest { collapse_id: None, ..request(PushLevel::Passive) }, NOW, T).await.unwrap(), Delivery::Sent);
        let s = seen.recv().await.unwrap();
        assert_eq!(s.headers.get("apns-priority").unwrap(), "5", "passive : priorité basse");
        assert!(s.headers.get("apns-collapse-id").is_none());
    }

    #[tokio::test]
    async fn maps_apns_answers() {
        let (url, _seen) = fake_apns(StatusCode::GONE, r#"{"reason":"Unregistered"}"#).await;
        assert_eq!(client(url).send(&request(PushLevel::Active), NOW, T).await.unwrap(), Delivery::Unregistered);
        let (url, _seen) = fake_apns(StatusCode::BAD_REQUEST, r#"{"reason":"BadDeviceToken"}"#).await;
        assert_eq!(client(url).send(&request(PushLevel::Active), NOW, T).await.unwrap(), Delivery::Rejected("BadDeviceToken".into()));
        let (url, _seen) = fake_apns(StatusCode::INTERNAL_SERVER_ERROR, r#"{"reason":"InternalServerError"}"#).await;
        assert!(matches!(client(url).send(&request(PushLevel::Active), NOW, T).await, Err(UpstreamError::Unavailable(_))));
        let (url, _seen) = fake_apns(StatusCode::FORBIDDEN, r#"{"reason":"ExpiredProviderToken"}"#).await;
        let c = client(url);
        let before = c.provider_token(NOW);
        assert!(matches!(c.send(&request(PushLevel::Active), NOW, T).await, Err(UpstreamError::Unavailable(_))));
        assert_ne!(c.provider_token(NOW + 1), before, "jeton fournisseur oublié après ExpiredProviderToken");
    }

    #[tokio::test]
    async fn bad_device_token_is_refused_without_request() {
        let (url, mut seen) = fake_apns(StatusCode::OK, "").await;
        let r = PushRequest { device: "../../autre".into(), ..request(PushLevel::Active) };
        assert!(matches!(client(url).send(&r, NOW, T).await.unwrap(), Delivery::Rejected(_)));
        assert!(seen.try_recv().is_err(), "aucune requête envoyée");
    }

    #[tokio::test]
    async fn unreachable_apns_is_unavailable() {
        let c = client("http://127.0.0.1:9".into());
        assert!(matches!(c.send(&request(PushLevel::Active), NOW, T).await, Err(UpstreamError::Unavailable(_))));
    }
}
