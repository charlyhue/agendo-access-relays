//! Poignée de main d'un tunnel, côté relais.
//!
//! ```text
//! maison                                   relais
//!   HELLO { min, max }            ──▶      version commune ? sinon GOAWAY 5
//!                                 ◀──      CHALLENGE { version, nonce }
//!   AUTH { jeton, signature }     ──▶      verify_auth ; sinon GOAWAY 2 (4 si jeton expiré)
//!                                 ◀──      READY { host, fenêtre initiale, ping }
//! ```
//!
//! Toute autre trame avant `READY` est une faute de protocole (`GOAWAY` 3). Le tout tient dans
//! le délai de poignée de main ; au-delà, la connexion est fermée sans un mot.

use std::time::Duration;

use agendo_access_protocol::{
    frame::{Frame, GoAwayCode},
    keys::TrustedKeys,
    token::{TokenError, TunnelClaims},
    tunnel::{AuthError, negotiate, verify_auth},
};
use tokio::io::{AsyncRead, AsyncWrite};

use agendo_access_protocol::frame::MAX_GOAWAY_MESSAGE;

use crate::wire::{FrameReader, WireError, write_frame};

/// Ce que le relais sait pour accepter un tunnel.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeParams<'a> {
    pub keys: &'a TrustedKeys,
    /// `ZONE_MAISONS`.
    pub zone: &'a str,
    /// Plage de versions parlées par le relais.
    pub versions: (u16, u16),
    pub initial_window: u32,
    pub ping_interval: Duration,
    pub timeout: Duration,
    /// Heure Unix de la vérification du jeton.
    pub now: i64,
}

/// Tunnel accepté.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub claims: TunnelClaims,
    pub version: u16,
    /// Défi de la session, gardé pour vérifier les `RENEW`.
    pub nonce: [u8; 32],
}

/// Échec de la poignée de main. `Refused` a déjà été signifié à la maison par `GOAWAY`.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("tunnel refusé ({code:?}) : {reason}")]
    Refused { code: GoAwayCode, reason: String },
    #[error("délai de poignée de main dépassé")]
    Timeout,
    #[error("connexion fermée pendant la poignée de main")]
    Closed,
    #[error("erreur pendant la poignée de main : {0}")]
    Wire(String),
}

/// Mène la poignée de main sur `io`. Le lecteur `reader` garde les octets déjà reçus pour la
/// suite (trames arrivées juste après `AUTH`).
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    reader: &mut FrameReader,
    params: &HandshakeParams<'_>,
) -> Result<Accepted, HandshakeError> {
    tokio::time::timeout(params.timeout, run(io, reader, params)).await.unwrap_or(Err(HandshakeError::Timeout))
}

async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    reader: &mut FrameReader,
    params: &HandshakeParams<'_>,
) -> Result<Accepted, HandshakeError> {
    let Frame::Hello { min, max } = next(io, reader).await? else {
        return Err(refuse(io, GoAwayCode::ProtocolError, "HELLO attendu".into()).await);
    };
    let Some(version) = negotiate((min, max), params.versions) else {
        let (low, high) = params.versions;
        let reason = format!("aucune version commune : maison {min} à {max}, relais {low} à {high}");
        return Err(refuse(io, GoAwayCode::UnsupportedVersion, reason).await);
    };
    let nonce = new_nonce();
    send(io, &Frame::Challenge { version, nonce }).await?;
    let Frame::Auth { token, signature } = next(io, reader).await? else {
        return Err(refuse(io, GoAwayCode::ProtocolError, "AUTH attendu".into()).await);
    };
    let claims = match verify_auth(&token, &signature, &nonce, params.keys, params.zone, params.now) {
        Ok(claims) => claims,
        Err(AuthError::Token(TokenError::Expired)) => {
            return Err(refuse(io, GoAwayCode::TokenExpired, "jeton de tunnel expiré".into()).await);
        }
        Err(e) => return Err(refuse(io, GoAwayCode::AuthFailed, e.to_string()).await),
    };
    let ping_interval_secs = u32::try_from(params.ping_interval.as_secs()).unwrap_or(u32::MAX).max(1);
    send(io, &Frame::Ready { host: claims.host.clone(), initial_window: params.initial_window, ping_interval_secs }).await?;
    Ok(Accepted { claims, version, nonce })
}

fn new_nonce() -> [u8; 32] {
    agendo_access_protocol::frame::new_nonce()
}

/// Trame suivante de la maison ; un `GOAWAY` de sa part ou la fin du flux ferment.
async fn next<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, reader: &mut FrameReader) -> Result<Frame, HandshakeError> {
    match reader.read(io).await {
        Ok(Some(Frame::GoAway { .. }) | None) => Err(HandshakeError::Closed),
        Ok(Some(frame)) => Ok(frame),
        Err(WireError::Frame(e)) => Err(refuse(io, GoAwayCode::ProtocolError, e.to_string()).await),
        Err(WireError::Io(e)) => Err(HandshakeError::Wire(e.kind().to_string())),
    }
}

async fn send<S: AsyncWrite + Unpin>(io: &mut S, frame: &Frame) -> Result<(), HandshakeError> {
    write_frame(io, frame).await.map_err(|e| HandshakeError::Wire(e.to_string()))
}

/// Signifie le refus par `GOAWAY` (au mieux) et rend l'erreur.
async fn refuse<S: AsyncWrite + Unpin>(io: &mut S, code: GoAwayCode, reason: String) -> HandshakeError {
    let _ = write_frame(io, &Frame::GoAway { code, message: truncate(&reason, MAX_GOAWAY_MESSAGE).to_owned() }).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(io).await;
    HandshakeError::Refused { code, reason }
}

/// Début de `text` d'au plus `max` octets, coupé entre deux caractères.
pub fn truncate(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use agendo_access_protocol::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, SigningKey, frame::FrameType};
    use tokio::io::DuplexStream;

    use super::*;
    use crate::testkit::{HOST, HouseConn, ZONE, house_key, trusted_keys, tunnel_token};

    /// Lance la poignée de main côté relais ; rend le bout maison et la tâche du relais.
    fn start(timeout: Duration) -> (HouseConn<DuplexStream>, tokio::task::JoinHandle<Result<Accepted, HandshakeError>>) {
        let (house, mut relay) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let keys = trusted_keys();
            let params = HandshakeParams {
                keys: &keys,
                zone: ZONE,
                versions: (MIN_PROTOCOL_VERSION, PROTOCOL_VERSION),
                initial_window: 256 * 1024,
                ping_interval: Duration::from_secs(25),
                timeout,
                now: relay_common::time::now_unix(),
            };
            handshake(&mut relay, &mut FrameReader::new(), &params).await
        });
        (HouseConn::new(house), task)
    }

    fn goaway_code(frame: Frame) -> GoAwayCode {
        match frame {
            Frame::GoAway { code, message } => {
                assert!(!message.is_empty(), "raison attendue");
                code
            }
            other => panic!("GOAWAY attendu, reçu {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepted_handshake() {
        let (mut house, task) = start(Duration::from_secs(5));
        let ready = house.handshake(HOST).await;
        assert_eq!(ready, Frame::Ready { host: HOST.into(), initial_window: 256 * 1024, ping_interval_secs: 25 });
        let accepted = task.await.unwrap().unwrap();
        assert_eq!(accepted.claims.host, HOST);
        assert_eq!(accepted.version, PROTOCOL_VERSION);
        assert_eq!(Some(accepted.nonce), house.nonce, "le relais garde le défi de la session");
    }

    #[tokio::test]
    async fn no_common_version() {
        let (mut house, task) = start(Duration::from_secs(5));
        house.send(&Frame::Hello { min: PROTOCOL_VERSION + 1, max: PROTOCOL_VERSION + 3 }).await;
        assert_eq!(goaway_code(house.recv().await.unwrap()), GoAwayCode::UnsupportedVersion);
        assert!(matches!(task.await.unwrap(), Err(HandshakeError::Refused { code: GoAwayCode::UnsupportedVersion, .. })));
    }

    #[tokio::test]
    async fn bad_nonce_signature_is_refused() {
        let (mut house, task) = start(Duration::from_secs(5));
        let other = SigningKey::from_bytes(&[9; 32]);
        let frame = house.handshake_with(&tunnel_token(HOST, 3600), &other).await;
        assert_eq!(goaway_code(frame), GoAwayCode::AuthFailed);
        assert!(matches!(task.await.unwrap(), Err(HandshakeError::Refused { .. })));
    }

    #[tokio::test]
    async fn host_outside_zone_and_unknown_kid_are_refused() {
        let (mut house, _task) = start(Duration::from_secs(5));
        let frame = house.handshake_with(&tunnel_token("abcdefghijklmnop.ailleurs.fr", 3600), &house_key()).await;
        assert_eq!(goaway_code(frame), GoAwayCode::AuthFailed);

        let (mut house, _task) = start(Duration::from_secs(5));
        let mut claims = agendo_access_protocol::token::TunnelClaims {
            iss: "x".into(),
            sub: "x".into(),
            host: HOST.into(),
            house_key: agendo_access_protocol::keys::encode_public_key(&house_key().verifying_key()),
            iat: relay_common::time::now_unix(),
            exp: relay_common::time::now_unix() + 60,
        };
        claims.sub = "maison".into();
        let token = claims.sign("k-inconnu", &crate::testkit::plane_key());
        assert_eq!(goaway_code(house.handshake_with(&token, &house_key()).await), GoAwayCode::AuthFailed);
    }

    #[tokio::test]
    async fn expired_token_gets_token_expired() {
        let (mut house, _task) = start(Duration::from_secs(5));
        let frame = house.handshake_with(&tunnel_token(HOST, -1), &house_key()).await;
        assert_eq!(goaway_code(frame), GoAwayCode::TokenExpired);
    }

    #[tokio::test]
    async fn data_before_ready_is_a_protocol_error() {
        let (mut house, task) = start(Duration::from_secs(5));
        house.send(&Frame::Data { stream: 1, data: vec![1] }).await;
        assert_eq!(goaway_code(house.recv().await.unwrap()), GoAwayCode::ProtocolError);
        assert!(matches!(task.await.unwrap(), Err(HandshakeError::Refused { code: GoAwayCode::ProtocolError, .. })));

        let (mut house, _task) = start(Duration::from_secs(5));
        house.send(&Frame::Hello { min: 1, max: 1 }).await;
        assert_eq!(house.recv().await.map(|f| f.kind()), Some(FrameType::Challenge));
        house.send(&Frame::Hello { min: 1, max: 1 }).await;
        assert_eq!(goaway_code(house.recv().await.unwrap()), GoAwayCode::ProtocolError, "HELLO au lieu d'AUTH");

        let (mut house, _task) = start(Duration::from_secs(5));
        house.send(&Frame::Hello { min: 1, max: 1 }).await;
        let Some(Frame::Challenge { nonce, .. }) = house.recv().await else { panic!("CHALLENGE attendu") };
        house.send(&agendo_access_protocol::tunnel::renew_frame(&tunnel_token(HOST, 3600), &house_key(), &nonce)).await;
        assert_eq!(goaway_code(house.recv().await.unwrap()), GoAwayCode::ProtocolError, "RENEW avant READY");
    }

    #[tokio::test]
    async fn silent_house_times_out() {
        let (mut house, task) = start(Duration::from_millis(100));
        assert!(matches!(task.await.unwrap(), Err(HandshakeError::Timeout)));
        assert_eq!(house.recv().await, None, "fermé sans un mot");
    }

    #[tokio::test]
    async fn garbage_is_a_protocol_error() {
        use tokio::io::AsyncWriteExt;
        let (mut house, task) = start(Duration::from_secs(5));
        house.io.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(task.await.unwrap(), Err(HandshakeError::Refused { code: GoAwayCode::ProtocolError, .. })));
    }
}
