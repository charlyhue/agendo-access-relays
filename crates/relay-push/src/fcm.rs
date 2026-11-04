//! Client FCM HTTP v1 : message de **données** seul (`agendo_key_id`, `agendo_ciphertext`),
//! que l'app déchiffre. Authentification OAuth 2.0 par compte de service : assertion JWT RS256
//! échangée contre un jeton d'accès, mis en cache jusqu'à 5 minutes avant son expiration.
//!
//! Le compte de service est un fichier JSON monté, jamais une variable d'environnement.

use std::{
    sync::{Mutex, PoisonError},
    time::Duration,
};

use agendo_access_protocol::{
    b64,
    push::{FCM_CIPHERTEXT, FCM_KEY_ID, PushLevel, PushRequest},
};
use ring::signature::RsaKeyPair;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::delivery::{Delivery, UpstreamError};

/// URL de FCM.
pub const FCM_URL: &str = "https://fcm.googleapis.com";
/// Portée OAuth de l'envoi de messages.
pub const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Marge avant l'expiration du jeton d'accès.
const TOKEN_MARGIN_SECS: i64 = 300;

/// Compte de service Google (fichier JSON de la console Firebase).
pub struct ServiceAccount {
    pub project_id: String,
    pub client_email: String,
    pub token_uri: String,
    key: RsaKeyPair,
}

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Jamais la clé.
        f.debug_struct("ServiceAccount")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .finish_non_exhaustive()
    }
}

/// Fichier de compte de service illisible (sans en citer le contenu).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceAccountError {
    #[error("compte de service FCM : JSON illisible ou champ manquant")]
    Json,
    #[error("compte de service FCM : clé privée illisible (RSA PKCS#8 PEM attendue)")]
    Key,
}

/// Relit le fichier JSON d'un compte de service.
pub fn parse_service_account(json: &str) -> Result<ServiceAccount, ServiceAccountError> {
    #[derive(Deserialize)]
    struct File {
        project_id: String,
        private_key: String,
        client_email: String,
        token_uri: String,
    }
    let file: File = serde_json::from_str(json).map_err(|_| ServiceAccountError::Json)?;
    let der = pem_body(&file.private_key).ok_or(ServiceAccountError::Key)?;
    let key = RsaKeyPair::from_pkcs8(&der).map_err(|_| ServiceAccountError::Key)?;
    Ok(ServiceAccount { project_id: file.project_id, client_email: file.client_email, token_uri: file.token_uri, key })
}

/// Contenu d'un bloc PEM `PRIVATE KEY`.
fn pem_body(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let body = pem.split("-----BEGIN PRIVATE KEY-----").nth(1)?.split("-----END PRIVATE KEY-----").next()?;
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact).ok()
}

/// Corps de `messages:send`.
pub fn message(request: &PushRequest) -> Value {
    let priority = if request.level == PushLevel::Passive { "NORMAL" } else { "HIGH" };
    let mut android = json!({ "priority": priority });
    if let (Some(collapse), Some(android)) = (&request.collapse_id, android.as_object_mut()) {
        android.insert("collapse_key".into(), json!(collapse));
    }
    json!({
        "message": {
            "token": request.device,
            "data": { FCM_KEY_ID: request.key_id, FCM_CIPHERTEXT: request.ciphertext },
            "android": android,
        }
    })
}

/// Code d'erreur FCM (`details[].errorCode`, sinon `error.status`), réduit à des caractères sûrs.
fn error_code(body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let error = &v["error"];
    let code = error["details"]
        .as_array()
        .and_then(|d| d.iter().find_map(|d| d["errorCode"].as_str()))
        .or_else(|| error["status"].as_str())
        .unwrap_or("inconnue");
    code.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect()
}

/// Client FCM.
#[derive(Debug)]
pub struct FcmClient {
    account: ServiceAccount,
    base_url: String,
    http: reqwest::Client,
    token: Mutex<Option<(String, i64)>>,
}

impl FcmClient {
    pub fn new(account: ServiceAccount, base_url: String, http: reqwest::Client) -> Self {
        Self { account, base_url, http, token: Mutex::new(None) }
    }

    /// Assertion JWT RS256 du compte de service.
    pub fn assertion(&self, now: i64) -> Result<String, UpstreamError> {
        let header = json!({ "alg": "RS256", "typ": "JWT" });
        let claims = json!({
            "iss": self.account.client_email,
            "scope": SCOPE,
            "aud": self.account.token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let mut signature = vec![0u8; self.account.key.public().modulus_len()];
        self.account
            .key
            .sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut signature)
            .map_err(|_| UpstreamError::Unavailable("signature de l'assertion OAuth impossible".into()))?;
        Ok(format!("{input}.{}", b64(&signature)))
    }

    /// Jeton d'accès OAuth, demandé au besoin.
    async fn access_token(&self, now: i64, timeout: Duration) -> Result<String, UpstreamError> {
        if let Some((token, expires)) = self.token.lock().unwrap_or_else(PoisonError::into_inner).as_ref()
            && now < *expires
        {
            return Ok(token.clone());
        }
        #[derive(Deserialize)]
        struct Answer {
            access_token: String,
            expires_in: i64,
        }
        let body = format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}", self.assertion(now)?);
        let response = self
            .http
            .post(&self.account.token_uri)
            .timeout(timeout)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| UpstreamError::Unavailable(format!("OAuth Google : {}", e.without_url())))?;
        if !response.status().is_success() {
            return Err(UpstreamError::Unavailable(format!("OAuth Google {}", response.status())));
        }
        let answer: Answer = response.json().await.map_err(|_| UpstreamError::Unavailable("OAuth Google : réponse illisible".into()))?;
        let expires = now + answer.expires_in - TOKEN_MARGIN_SECS;
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = Some((answer.access_token.clone(), expires));
        Ok(answer.access_token)
    }

    fn forget_access_token(&self) {
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Envoie à FCM.
    pub async fn send(&self, request: &PushRequest, now: i64, timeout: Duration) -> Result<Delivery, UpstreamError> {
        let token = self.access_token(now, timeout).await?;
        let url = format!("{}/v1/projects/{}/messages:send", self.base_url.trim_end_matches('/'), self.account.project_id);
        let response = self
            .http
            .post(url)
            .timeout(timeout)
            .bearer_auth(token)
            .json(&message(request))
            .send()
            .await
            .map_err(|e| UpstreamError::Unavailable(format!("FCM : {}", e.without_url())))?;
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let code = error_code(&body);
        match status.as_u16() {
            200 => Ok(Delivery::Sent),
            _ if code == "UNREGISTERED" => Ok(Delivery::Unregistered),
            401 | 403 => {
                self.forget_access_token();
                Err(UpstreamError::Unavailable(format!("FCM {status} {code}")))
            }
            429 | 500..=599 => Err(UpstreamError::Unavailable(format!("FCM {status} {code}"))),
            _ => Ok(Delivery::Rejected(code)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use agendo_access_protocol::{push::Platform, unb64};
    use axum::{
        Form, Json, Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use base64::Engine;
    use ring::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use tokio::sync::mpsc;

    use super::*;

    const KEY_DER: &[u8] = include_bytes!("../tests/fixtures/cle-rsa-de-test.pk8");
    const NOW: i64 = 1_793_000_000;
    const T: Duration = Duration::from_secs(5);

    pub(crate) fn service_account_json(token_uri: &str) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(KEY_DER);
        let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", lines.join("\n"));
        json!({
            "type": "service_account",
            "project_id": "agendo-test",
            "private_key_id": "abc",
            "private_key": pem,
            "client_email": "relais@agendo-test.iam.gserviceaccount.com",
            "token_uri": token_uri,
        })
        .to_string()
    }

    pub(crate) fn request(level: PushLevel) -> PushRequest {
        PushRequest {
            device: "fcm:jeton-du-telephone_123".into(),
            platform: Platform::Android,
            level,
            collapse_id: Some("sonnette-entree".into()),
            key_id: "cle-1".into(),
            ciphertext: "Y2hpZmZyZQ".into(),
        }
    }

    #[derive(Clone)]
    pub(crate) struct Fake {
        pub token_calls: Arc<AtomicUsize>,
        pub sent: Arc<mpsc::UnboundedSender<(String, HeaderMap, Value)>>,
        pub status: StatusCode,
        pub body: &'static str,
    }

    /// Faux Google : `POST /token` (vérifie l'assertion) et `POST /v1/projects/{p}/messages:send`.
    pub(crate) async fn fake_fcm(status: StatusCode, body: &'static str) -> (String, Fake, mpsc::UnboundedReceiver<(String, HeaderMap, Value)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let fake = Fake { token_calls: Arc::default(), sent: Arc::new(tx), status, body };
        let app = Router::new()
            .route(
                "/token",
                post(|State(f): State<Fake>, Form(form): Form<std::collections::HashMap<String, String>>| async move {
                    assert_eq!(form["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
                    let parts: Vec<&str> = form["assertion"].split('.').collect();
                    let pair = RsaKeyPair::from_pkcs8(KEY_DER).unwrap();
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public_key().as_ref())
                        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &unb64(parts[2]).unwrap())
                        .unwrap();
                    let claims: Value = serde_json::from_slice(&unb64(parts[1]).unwrap()).unwrap();
                    assert_eq!(claims["scope"], SCOPE);
                    assert_eq!(claims["iss"], "relais@agendo-test.iam.gserviceaccount.com");
                    f.token_calls.fetch_add(1, Ordering::SeqCst);
                    Json(json!({ "access_token": "jeton-acces-1", "expires_in": 3600, "token_type": "Bearer" }))
                }),
            )
            .route(
                "/v1/projects/{project}/messages:send",
                post(|State(f): State<Fake>, Path(project): Path<String>, headers: HeaderMap, Json(body): Json<Value>| async move {
                    f.sent.send((project, headers, body)).unwrap();
                    (f.status, f.body)
                }),
            )
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, fake, rx)
    }

    pub(crate) fn client(url: &str) -> FcmClient {
        let account = parse_service_account(&service_account_json(&format!("{url}/token"))).unwrap();
        FcmClient::new(account, url.to_owned(), reqwest::Client::new())
    }

    #[test]
    fn parses_service_account_without_leaking_it() {
        let a = parse_service_account(&service_account_json("https://oauth2.googleapis.com/token")).unwrap();
        assert_eq!(a.project_id, "agendo-test");
        assert!(!format!("{a:?}").contains("PRIVATE"));
        assert_eq!(parse_service_account("{}").unwrap_err(), ServiceAccountError::Json);
        let broken = service_account_json("x").replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----AAAA");
        assert_ne!(broken, service_account_json("x"));
        assert_eq!(parse_service_account(&broken).unwrap_err(), ServiceAccountError::Key);
    }

    #[test]
    fn message_is_data_only() {
        assert_eq!(
            message(&request(PushLevel::TimeSensitive)),
            json!({
                "message": {
                    "token": "fcm:jeton-du-telephone_123",
                    "data": { FCM_KEY_ID: "cle-1", FCM_CIPHERTEXT: "Y2hpZmZyZQ" },
                    "android": { "priority": "HIGH", "collapse_key": "sonnette-entree" },
                }
            })
        );
        let passive = message(&PushRequest { collapse_id: None, ..request(PushLevel::Passive) });
        assert_eq!(passive["message"]["android"], json!({ "priority": "NORMAL" }));
        assert!(passive["message"].get("notification").is_none(), "jamais de notification en clair");
    }

    #[tokio::test]
    async fn sends_with_cached_access_token() {
        let (url, fake, mut sent) = fake_fcm(StatusCode::OK, r#"{"name":"projects/agendo-test/messages/1"}"#).await;
        let c = client(&url);
        assert_eq!(c.send(&request(PushLevel::Active), NOW, T).await.unwrap(), Delivery::Sent);
        assert_eq!(c.send(&request(PushLevel::Critical), NOW + 60, T).await.unwrap(), Delivery::Sent);
        assert_eq!(fake.token_calls.load(Ordering::SeqCst), 1, "jeton d'accès réutilisé");
        let (project, headers, body) = sent.recv().await.unwrap();
        assert_eq!(project, "agendo-test");
        assert_eq!(headers["authorization"], "Bearer jeton-acces-1");
        assert_eq!(body, message(&request(PushLevel::Active)));
        // Proche de l'expiration : renouvelé.
        assert_eq!(c.send(&request(PushLevel::Active), NOW + 3600 - 299, T).await.unwrap(), Delivery::Sent);
        assert_eq!(fake.token_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn maps_fcm_answers() {
        let unregistered = r#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
        let (url, _f, _s) = fake_fcm(StatusCode::NOT_FOUND, unregistered).await;
        assert_eq!(client(&url).send(&request(PushLevel::Active), NOW, T).await.unwrap(), Delivery::Unregistered);
        let invalid = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"}]}}"#;
        let (url, _f, _s) = fake_fcm(StatusCode::BAD_REQUEST, invalid).await;
        assert_eq!(client(&url).send(&request(PushLevel::Active), NOW, T).await.unwrap(), Delivery::Rejected("INVALID_ARGUMENT".into()));
        let (url, _f, _s) = fake_fcm(StatusCode::SERVICE_UNAVAILABLE, "{}").await;
        assert!(matches!(client(&url).send(&request(PushLevel::Active), NOW, T).await, Err(UpstreamError::Unavailable(_))));
        let (url, f, _s) = fake_fcm(StatusCode::UNAUTHORIZED, "{}").await;
        let c = client(&url);
        assert!(matches!(c.send(&request(PushLevel::Active), NOW, T).await, Err(UpstreamError::Unavailable(_))));
        assert!(matches!(c.send(&request(PushLevel::Active), NOW, T).await, Err(UpstreamError::Unavailable(_))));
        assert_eq!(f.token_calls.load(Ordering::SeqCst), 2, "jeton d'accès oublié après 401");
    }
}
