//! Outillage de test : clés et jetons fixes, fausse maison côté tunnel. Compilé seulement pour
//! les tests (feature `testkit`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::time::Duration;

use agendo_access_protocol::{
    MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, SigningKey,
    frame::Frame,
    keys::{TrustedKey, TrustedKeys, encode_public_key},
    token::TunnelClaims,
    tunnel::{auth_frame, renew_frame},
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
    /// Défi de la session (reçu dans `CHALLENGE`), qui signe aussi les `RENEW`.
    pub nonce: Option<[u8; 32]>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HouseConn<S> {
    pub fn new(io: S) -> Self {
        Self { io, reader: FrameReader::new(), nonce: None }
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
        self.nonce = Some(nonce);
        self.send(&auth_frame(token, key, &nonce)).await;
        self.recv().await.expect("le relais a fermé avant READY")
    }

    /// `RENEW` avec `token`, signé par `key` avec le défi de la session.
    pub async fn renew(&mut self, token: &str, key: &SigningKey) {
        let nonce = self.nonce.expect("RENEW avant la poignée de main");
        self.send(&renew_frame(token, key, &nonce)).await;
    }

    /// Poignée de main réussie pour `host`.
    pub async fn handshake(&mut self, host: &str) -> Frame {
        let frame = self.handshake_with(&tunnel_token(host, 3600), &house_key()).await;
        assert!(matches!(frame, Frame::Ready { .. }), "READY attendu, reçu {frame:?}");
        frame
    }
}

// --- Maison qui sert du TLS par son tunnel -------------------------------------------------

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use agendo_access_protocol::frame::{CloseCode, MAX_PAYLOAD, RecvWindow, SendWindow};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{Mutex, Notify, mpsc},
};

/// Certificat auto-signé pour `host` : (configuration serveur, configuration client qui lui
/// fait confiance).
pub fn tls_pair(host: &str) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

struct HouseStream {
    send: std::sync::Mutex<SendWindow>,
    credit: Notify,
    to_app: mpsc::UnboundedSender<Vec<u8>>,
    recv: std::sync::Mutex<RecvWindow>,
}

/// Fait tourner une maison sur un tunnel déjà prêt (`READY` reçu, fenêtre `window`) : chaque
/// `OPEN` devient une connexion TLS servie par `tls`, dont l'application répond à chaque ligne
/// `écho <ligne> de <client>`.
pub async fn serve_tls<S>(conn: HouseConn<S>, window: u32, tls: Arc<rustls::ServerConfig>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let HouseConn { io, mut reader, .. } = conn;
    let (mut rd, mut wr) = tokio::io::split(io);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Frame>();
    tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if write_frame(&mut wr, &frame).await.is_err() {
                return;
            }
        }
    });
    let streams: Arc<Mutex<HashMap<u32, Arc<HouseStream>>>> = Arc::default();
    while let Ok(Some(frame)) = reader.read(&mut rd).await {
        match frame {
            Frame::Open { stream, client } => {
                let (app, pump) = tokio::io::duplex(1 << 20);
                let (to_app, from_relay) = mpsc::unbounded_channel();
                let s = Arc::new(HouseStream {
                    send: std::sync::Mutex::new(SendWindow::new(window)),
                    credit: Notify::new(),
                    to_app,
                    recv: std::sync::Mutex::new(RecvWindow::new(window)),
                });
                streams.lock().await.insert(stream, s.clone());
                tokio::spawn(pump_stream(stream, s, pump, from_relay, out_tx.clone()));
                tokio::spawn(echo_app(app, client, tls.clone()));
            }
            Frame::Data { stream, data } => {
                if let Some(s) = streams.lock().await.get(&stream) {
                    s.recv.lock().unwrap().receive(data.len()).unwrap();
                    let _ = s.to_app.send(data);
                }
            }
            Frame::Window { stream, increment } => {
                if let Some(s) = streams.lock().await.get(&stream) {
                    s.send.lock().unwrap().grant(increment).unwrap();
                    s.credit.notify_one();
                }
            }
            Frame::Close { stream, .. } => {
                streams.lock().await.remove(&stream);
            }
            Frame::Ping { ts } => {
                let _ = out_tx.send(Frame::Pong { ts });
            }
            _ => {}
        }
    }
}

async fn pump_stream(
    id: u32,
    s: Arc<HouseStream>,
    pump: tokio::io::DuplexStream,
    mut from_relay: mpsc::UnboundedReceiver<Vec<u8>>,
    out: mpsc::UnboundedSender<Frame>,
) {
    let (mut rd, mut wr) = tokio::io::split(pump);
    let out2 = out.clone();
    let s2 = s.clone();
    // Relais → application, crédit rendu une fois écrit.
    tokio::spawn(async move {
        while let Some(data) = from_relay.recv().await {
            if wr.write_all(&data).await.is_err() {
                return;
            }
            if let Some(credit) = s2.recv.lock().unwrap().release(data.len()) {
                let _ = out2.send(Frame::Window { stream: id, increment: credit });
            }
        }
        let _ = wr.shutdown().await;
    });
    // Application → relais, dans la limite du crédit.
    let mut buf = vec![0u8; MAX_PAYLOAD];
    loop {
        let available = loop {
            let a = s.send.lock().unwrap().available() as usize;
            if a > 0 {
                break a;
            }
            s.credit.notified().await;
        };
        let n = match rd.read(&mut buf[..available.min(MAX_PAYLOAD)]).await {
            Ok(0) | Err(_) => {
                let _ = out.send(Frame::Close { stream: id, code: CloseCode::Normal });
                return;
            }
            Ok(n) => n,
        };
        s.send.lock().unwrap().consume(n).unwrap();
        let _ = out.send(Frame::Data { stream: id, data: buf[..n].to_vec() });
    }
}

async fn echo_app(app: tokio::io::DuplexStream, client: SocketAddr, tls: Arc<rustls::ServerConfig>) {
    let Ok(tls) = tokio_rustls::TlsAcceptor::from(tls).accept(app).await else { return };
    let (rd, mut wr) = tokio::io::split(tls);
    let mut lines = BufReader::new(rd).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if wr.write_all(format!("écho {line} de {client}\n").as_bytes()).await.is_err() {
            return;
        }
        let _ = wr.flush().await;
    }
}

/// Client TLS qui passe par le port public du relais, avec l'en-tête PROXY de `source`.
pub async fn tls_client(
    public: SocketAddr,
    source: SocketAddr,
    host: &str,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut tcp = TcpStream::connect(public).await?;
    tcp.write_all(&crate::proxy_protocol::encode_v2(source, public)).await?;
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap();
    tokio_rustls::TlsConnector::from(config).connect(name, tcp).await
}
