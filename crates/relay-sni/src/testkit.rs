//! Outillage de test : clés et jetons fixes, fausse maison côté tunnel. Compilé seulement pour
//! les tests (feature `testkit`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::Duration;

use agendo_access_protocol::{
    MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, SigningKey,
    frame::Frame,
    keys::{TrustedKey, TrustedKeys, encode_public_key},
    token::TunnelClaims,
    tunnel::auth_frame,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::wire::{FrameReader, WireError, write_frame};

pub const ZONE: &str = "maisons.exemple.fr";
pub const HOST: &str = "abcdefghijklmnop.maisons.exemple.fr";
pub const OTHER_HOST: &str = "qrstuvwxyz234567.maisons.exemple.fr";

/// Clé du plan de contrôle (graine `[1; 32]`, comme les vecteurs du protocole).
pub fn plane_key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

/// Clé de la maison (graine `[2; 32]`).
pub fn house_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

/// Clés de confiance : `k1` → clé du plan de contrôle.
pub fn trusted_keys() -> TrustedKeys {
    TrustedKeys::new(vec![TrustedKey { kid: "k1".into(), key: encode_public_key(&plane_key().verifying_key()) }]).unwrap()
}

/// Jeton de tunnel signé par `k1` pour `host`, valable `lifetime` secondes à partir de maintenant.
pub fn tunnel_token(host: &str, lifetime: i64) -> String {
    let now = relay_common::time::now_unix();
    TunnelClaims {
        iss: "https://api.maisons.exemple.fr".into(),
        sub: format!("maison-{}", &host[..4]),
        host: host.into(),
        house_key: encode_public_key(&house_key().verifying_key()),
        iat: now - 10,
        exp: now + lifetime,
    }
    .sign("k1", &plane_key())
}

/// Bout « maison » d'un tunnel : envoi et réception de trames.
pub struct HouseConn<S> {
    pub io: S,
    reader: FrameReader,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HouseConn<S> {
    pub fn new(io: S) -> Self {
        Self { io, reader: FrameReader::new() }
    }

    pub async fn send(&mut self, frame: &Frame) {
        write_frame(&mut self.io, frame).await.unwrap();
    }

    /// Prochaine trame (5 s au plus) ; `None` si le relais a fermé.
    pub async fn recv(&mut self) -> Option<Frame> {
        match tokio::time::timeout(Duration::from_secs(5), self.reader.read(&mut self.io)).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(WireError::Io(_))) => None,
            Ok(Err(e)) => panic!("trame illisible du relais : {e}"),
            Err(_) => panic!("aucune trame du relais en 5 s"),
        }
    }

    /// Poignée de main complète avec `token` et la clé `key` ; rend la réponse finale du
    /// relais (`READY` ou `GOAWAY`).
    pub async fn handshake_with(&mut self, token: &str, key: &SigningKey) -> Frame {
        self.send(&Frame::Hello { min: MIN_PROTOCOL_VERSION, max: PROTOCOL_VERSION }).await;
        let nonce = match self.recv().await {
            Some(Frame::Challenge { nonce, .. }) => nonce,
            other => return other.expect("le relais a fermé avant CHALLENGE"),
        };
        self.send(&auth_frame(token, key, &nonce)).await;
        self.recv().await.expect("le relais a fermé avant READY")
    }

    /// Poignée de main réussie pour `host`.
    pub async fn handshake(&mut self, host: &str) -> Frame {
        let frame = self.handshake_with(&tunnel_token(host, 3600), &house_key()).await;
        assert!(matches!(frame, Frame::Ready { .. }), "READY attendu, reçu {frame:?}");
        frame
    }
}
