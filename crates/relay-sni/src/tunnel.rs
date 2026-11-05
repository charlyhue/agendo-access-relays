//! Tunnel d'une maison, après `READY` : multiplexeur des flux, contrôle de flux par flux,
//! ping, expiration et renouvellement du jeton (`RENEW` → `RENEWED`), `GOAWAY`.
//!
//! Pas de demi-fermeture : `CLOSE` ferme le flux dans les deux sens. Reçu de la maison, le relais
//! livre au client les octets déjà reçus puis ferme la connexion, ignore la suite du flux et ne
//! renvoie pas de `CLOSE`.
//!
//! Une tâche lit les trames de la maison et les répartit entre les flux ; une tâche écrit, seule
//! propriétaire de la moitié écriture, les trames de la file `out` (bornée). Chaque flux est
//! servi par la tâche de la connexion publique (`crate::public`) à travers un [`StreamHandle`].
//!
//! Mémoire bornée : ce que la maison envoie pour un flux est gardé jusqu'à son écriture chez le
//! client, et ne dépasse jamais la fenêtre accordée ([`RecvWindow`]) ; au-delà, `CLOSE` 3. Le
//! relais n'envoie pas plus que le crédit reçu ([`SendWindow`]).

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicI64, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use agendo_access_protocol::{
    frame::{CloseCode, Frame, GoAwayCode, MAX_GOAWAY_MESSAGE, MAX_MISSED_PINGS, RecvWindow, SendWindow},
    keys::TrustedKeys,
    token::TunnelClaims,
    tunnel::verify_renew,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Notify, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Limits,
    handshake::truncate,
    metrics::SniMetrics,
    registry::Registry,
    wire::{FrameReader, WireError},
};

/// Trames en attente d'écriture vers la maison, au plus.
const OUT_QUEUE: usize = 256;
/// Octets regroupés au plus dans une écriture.
const WRITE_BATCH: usize = 256 * 1024;

/// Accès partagé à un tunnel ouvert.
#[derive(Debug, Clone)]
pub struct TunnelHandle {
    shared: Arc<TunnelShared>,
}

#[derive(Debug)]
struct TunnelShared {
    id: u64,
    host: String,
    house: String,
    out: mpsc::Sender<Frame>,
    cancel: CancellationToken,
    table: Mutex<Table>,
    initial_window: u32,
    max_streams: usize,
    missed_pings: AtomicU32,
    end: Mutex<Option<String>>,
    metrics: SniMetrics,
    /// Jeton en vigueur et défi de la session, pour les `RENEW`.
    session: Mutex<Session>,
    /// Expiration du jeton en vigueur (secondes Unix), avancée par un `RENEW` accepté.
    expires_at: AtomicI64,
    keys: TrustedKeys,
    zone: String,
}

#[derive(Debug)]
struct Session {
    claims: TunnelClaims,
    nonce: [u8; 32],
}

#[derive(Debug, Default)]
struct Table {
    next: u32,
    streams: HashMap<u32, Arc<StreamShared>>,
    closed: bool,
}

#[derive(Debug)]
struct StreamShared {
    id: u32,
    state: Mutex<StreamState>,
    /// Réveille l'envoi vers la maison (crédit reçu, fermeture).
    credit: Notify,
    /// Réveille l'écriture vers le client (octets reçus, fermeture).
    inbound: Notify,
}

#[derive(Debug)]
struct StreamState {
    send: SendWindow,
    recv: RecvWindow,
    data: VecDeque<Vec<u8>>,
    /// Le flux est terminé : `CLOSE` reçu ou envoyé, ou tunnel fermé. Aucun `CLOSE` de plus.
    closed: bool,
    /// Terminé en faute (fenêtre dépassée) : ce qui restait à écrire est abandonné.
    aborted: bool,
}

/// Échec de l'ouverture d'un flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("tunnel fermé")]
    TunnelClosed,
    #[error("trop de flux ouverts sur ce tunnel")]
    TooManyStreams,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TunnelHandle {
    pub fn id(&self) -> u64 {
        self.shared.id
    }

    /// Nom d'hôte servi.
    pub fn host(&self) -> &str {
        &self.shared.host
    }

    /// Identifiant de la maison (`sub` du jeton).
    pub fn house(&self) -> &str {
        &self.shared.house
    }

    /// Ouvre un flux pour un client : `OPEN` part vers la maison.
    pub async fn open_stream(&self, client: SocketAddr) -> Result<StreamHandle, OpenError> {
        let shared = &self.shared;
        let stream = {
            let mut table = lock(&shared.table);
            if table.closed {
                return Err(OpenError::TunnelClosed);
            }
            if table.streams.len() >= shared.max_streams {
                return Err(OpenError::TooManyStreams);
            }
            let id = table.allocate();
            let stream = Arc::new(StreamShared::new(id, shared.initial_window));
            table.streams.insert(id, stream.clone());
            stream
        };
        shared.metrics.streams.inc();
        let handle = StreamHandle { tunnel: shared.clone(), stream };
        if shared.out.send(Frame::Open { stream: handle.stream.id, client }).await.is_err() {
            lock(&handle.stream.state).closed = true;
            return Err(OpenError::TunnelClosed);
        }
        Ok(handle)
    }

    /// Demande l'arrêt du tunnel par `GOAWAY`.
    pub fn goaway(&self, code: GoAwayCode, message: &str) {
        self.shared.goaway(code, message);
    }
}

impl Table {
    /// Numéro libre, non nul.
    fn allocate(&mut self) -> u32 {
        loop {
            self.next = self.next.wrapping_add(1);
            if self.next != 0 && !self.streams.contains_key(&self.next) {
                return self.next;
            }
        }
    }
}

impl StreamShared {
    fn new(id: u32, window: u32) -> Self {
        Self {
            id,
            state: Mutex::new(StreamState {
                send: SendWindow::new(window),
                recv: RecvWindow::new(window),
                data: VecDeque::new(),
                closed: false,
                aborted: false,
            }),
            credit: Notify::new(),
            inbound: Notify::new(),
        }
    }

    fn wake(&self) {
        self.credit.notify_one();
        self.inbound.notify_one();
    }
}

impl TunnelShared {
    fn set_end(&self, reason: impl Into<String>) {
        lock(&self.end).get_or_insert_with(|| reason.into());
    }

    fn goaway(&self, code: GoAwayCode, message: &str) {
        self.set_end(format!("GOAWAY {code:?} : {message}"));
        let _ = self.out.try_send(Frame::GoAway { code, message: truncate(message, MAX_GOAWAY_MESSAGE).to_owned() });
        self.cancel.cancel();
    }

    fn stream(&self, id: u32) -> Option<Arc<StreamShared>> {
        lock(&self.table).streams.get(&id).cloned()
    }

    /// Le tunnel est fini : plus d'ouverture, tous les flux terminés.
    fn close_all(&self) {
        self.cancel.cancel();
        let streams: Vec<_> = {
            let mut table = lock(&self.table);
            table.closed = true;
            table.streams.values().cloned().collect()
        };
        for s in streams {
            lock(&s.state).closed = true;
            s.wake();
        }
    }

    /// Trame reçue de la maison ; `Err` : le tunnel est à fermer, pour cette raison.
    async fn dispatch(&self, frame: Frame) -> Result<(), String> {
        match frame {
            Frame::Data { stream, data } => self.on_data(stream, data).await,
            Frame::Window { stream, increment } => self.on_window(stream, increment).await,
            Frame::Close { stream, .. } => {
                if let Some(s) = self.stream(stream) {
                    lock(&s.state).closed = true;
                    s.wake();
                }
            }
            Frame::Ping { ts } => {
                let _ = self.out.send(Frame::Pong { ts }).await;
            }
            Frame::Pong { .. } => self.missed_pings.store(0, Ordering::Relaxed),
            Frame::Renew { token, signature } => return self.on_renew(&token, &signature).await,
            Frame::GoAway { code, .. } => return Err(format!("GOAWAY de la maison ({code:?})")),
            other => {
                let reason = format!("trame {:?} inattendue de la maison", other.kind());
                self.goaway(GoAwayCode::ProtocolError, &reason);
                return Err(reason);
            }
        }
        Ok(())
    }

    /// `RENEW` : jeton neuf pour la même maison et le même hôte, signé avec le défi de la
    /// session. Accepté, il remplace le jeton en vigueur et son expiration ; sinon `GOAWAY` 2.
    async fn on_renew(&self, token: &str, signature: &[u8; 64]) -> Result<(), String> {
        let now = relay_common::time::now_unix();
        let verdict = {
            let session = lock(&self.session);
            verify_renew(token, signature, &session.nonce, &session.claims, &self.keys, &self.zone, now)
        };
        match verdict {
            Ok(claims) => {
                let expires_at = claims.exp;
                self.expires_at.store(expires_at, Ordering::Relaxed);
                lock(&self.session).claims = claims;
                self.metrics.renewals_accepted.inc();
                tracing::info!(maison = %self.house, hote = %self.host, expiration = expires_at, "jeton du tunnel renouvelé");
                let expires_at = u64::try_from(expires_at).unwrap_or(0);
                let _ = self.out.send(Frame::Renewed { expires_at }).await;
                Ok(())
            }
            Err(error) => {
                self.metrics.renewals_refused.inc();
                let reason = format!("renouvellement refusé : {error}");
                self.goaway(GoAwayCode::AuthFailed, &reason);
                Err(reason)
            }
        }
    }

    async fn on_data(&self, id: u32, data: Vec<u8>) {
        // Flux inconnu : fermé de notre côté, des octets étaient en route. Ignoré.
        let Some(s) = self.stream(id) else { return };
        let len = data.len();
        let overflow = {
            let mut st = lock(&s.state);
            if st.closed {
                return;
            }
            if st.recv.receive(len).is_err() {
                st.closed = true;
                st.aborted = true;
                st.data.clear();
                true
            } else {
                st.data.push_back(data);
                false
            }
        };
        s.wake();
        if overflow {
            let _ = self.out.send(Frame::Close { stream: id, code: CloseCode::FlowControl }).await;
        } else {
            self.metrics.bytes_to_client.add(len as u64);
        }
    }

    async fn on_window(&self, id: u32, increment: u32) {
        let Some(s) = self.stream(id) else { return };
        let overflow = {
            let mut st = lock(&s.state);
            if st.closed {
                return;
            }
            if st.send.grant(increment).is_err() {
                st.closed = true;
                st.aborted = true;
                true
            } else {
                false
            }
        };
        s.wake();
        if overflow {
            let _ = self.out.send(Frame::Close { stream: id, code: CloseCode::FlowControl }).await;
        }
    }
}

/// Bout « relais » d'un flux, tenu par la tâche de la connexion publique.
#[derive(Debug)]
pub struct StreamHandle {
    tunnel: Arc<TunnelShared>,
    stream: Arc<StreamShared>,
}

impl StreamHandle {
    /// Attend un crédit d'envoi non nul ; `None` si le flux est terminé.
    pub async fn credit(&self) -> Option<usize> {
        loop {
            {
                let st = lock(&self.stream.state);
                if st.closed {
                    return None;
                }
                let available = st.send.available() as usize;
                if available > 0 {
                    return Some(available);
                }
            }
            self.stream.credit.notified().await;
        }
    }

    /// Envoie des octets du client à la maison (au plus le crédit rendu par [`Self::credit`]).
    pub async fn send(&self, data: Vec<u8>) -> bool {
        let len = data.len();
        {
            let mut st = lock(&self.stream.state);
            if st.closed || st.send.consume(len).is_err() {
                return false;
            }
        }
        self.tunnel.metrics.bytes_to_house.add(len as u64);
        self.tunnel.out.send(Frame::Data { stream: self.stream.id, data }).await.is_ok()
    }

    /// Prochains octets de la maison pour le client ; `None` à la fin du flux.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        loop {
            {
                let mut st = lock(&self.stream.state);
                if st.aborted {
                    return None;
                }
                if let Some(data) = st.data.pop_front() {
                    return Some(data);
                }
                if st.closed {
                    return None;
                }
            }
            self.stream.inbound.notified().await;
        }
    }

    /// `n` octets reçus ont été écrits chez le client : rend du crédit à la maison.
    pub async fn release(&self, n: usize) {
        let credit = {
            let mut st = lock(&self.stream.state);
            if st.closed {
                return;
            }
            st.recv.release(n)
        };
        if let Some(increment) = credit {
            let _ = self.tunnel.out.send(Frame::Window { stream: self.stream.id, increment }).await;
        }
    }

    /// Termine le flux de notre côté : `CLOSE` part, sauf si la maison l'a déjà fermé.
    pub async fn close(self, code: CloseCode) {
        let needed = {
            let mut st = lock(&self.stream.state);
            !std::mem::replace(&mut st.closed, true)
        };
        if needed {
            let _ = self.tunnel.out.send(Frame::Close { stream: self.stream.id, code }).await;
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        let needed = {
            let mut st = lock(&self.stream.state);
            !std::mem::replace(&mut st.closed, true)
        };
        lock(&self.tunnel.table).streams.remove(&self.stream.id);
        self.tunnel.metrics.streams.dec();
        if needed {
            // Fin sans `close` explicite (tâche interrompue) : la maison doit le savoir.
            let frame = Frame::Close { stream: self.stream.id, code: CloseCode::Error };
            if let Err(mpsc::error::TrySendError::Full(frame)) = self.tunnel.out.try_send(frame)
                && let Ok(runtime) = tokio::runtime::Handle::try_current()
            {
                let out = self.tunnel.out.clone();
                runtime.spawn(async move {
                    let _ = out.send(frame).await;
                });
            }
        }
    }
}

/// Ce qu'il faut pour servir un tunnel accepté.
pub struct TunnelSetup<'a> {
    pub id: u64,
    pub claims: TunnelClaims,
    /// Défi de la session (`CHALLENGE`), qui signe aussi les `RENEW`.
    pub nonce: [u8; 32],
    pub keys: &'a TrustedKeys,
    /// `ZONE_MAISONS`.
    pub zone: &'a str,
    pub peer_ip: IpAddr,
    pub limits: &'a Limits,
    pub registry: &'a Registry,
    pub metrics: &'a SniMetrics,
    /// Annulé à l'arrêt du relais.
    pub shutdown: &'a CancellationToken,
}

/// Sert un tunnel jusqu'à sa fin. Inscrit la maison, remplace une connexion plus ancienne du
/// même nom, la désinscrit à la fin.
pub async fn serve<S>(io: S, reader: FrameReader, setup: TunnelSetup<'_>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let TunnelSetup { id, claims, nonce, keys, zone, peer_ip, limits, registry, metrics, shutdown } = setup;
    let (out, out_rx) = mpsc::channel(OUT_QUEUE);
    let shared = Arc::new(TunnelShared {
        id,
        host: claims.host.clone(),
        house: claims.sub.clone(),
        out,
        cancel: CancellationToken::new(),
        table: Mutex::default(),
        initial_window: limits.initial_window,
        max_streams: limits.max_streams_per_tunnel,
        missed_pings: AtomicU32::new(0),
        end: Mutex::new(None),
        metrics: metrics.clone(),
        expires_at: AtomicI64::new(claims.exp),
        session: Mutex::new(Session { claims: claims.clone(), nonce }),
        keys: keys.clone(),
        zone: zone.to_owned(),
    });
    let handle = TunnelHandle { shared: shared.clone() };
    if let Some(old) = registry.register(handle) {
        metrics.tunnels_replaced.inc();
        old.goaway(GoAwayCode::Replaced, "remplacé par une connexion plus récente");
    }
    metrics.tunnels.inc();
    let started = Instant::now();
    tracing::info!(maison = %claims.sub, hote = %claims.host, ip = %peer_ip, "tunnel ouvert");

    let (mut rd, wr) = tokio::io::split(io);
    let writer = tokio::spawn(write_loop(wr, out_rx, shared.cancel.clone(), limits.write_timeout));
    let reason = tokio::select! {
        reason = read_loop(&mut rd, reader, &shared) => reason,
        reason = ping_loop(&shared, limits.ping_interval) => reason,
        reason = expiry(&shared) => reason,
        () = shutdown.cancelled() => {
            shared.goaway(GoAwayCode::Shutdown, "arrêt du relais (redéploiement)");
            "arrêt du relais".to_owned()
        }
        () = shared.cancel.cancelled() => lock(&shared.end).clone().unwrap_or_default(),
    };
    shared.set_end(reason);
    shared.close_all();
    registry.unregister(&shared.host, id);
    metrics.tunnels.dec();
    let _ = tokio::time::timeout(limits.write_timeout, writer).await;
    let reason = lock(&shared.end).clone().unwrap_or_default();
    tracing::info!(
        maison = %shared.house,
        hote = %shared.host,
        ip = %peer_ip,
        duree_s = started.elapsed().as_secs(),
        raison = %reason,
        "tunnel fermé"
    );
}

async fn read_loop<R: AsyncRead + Unpin>(rd: &mut R, mut reader: FrameReader, shared: &TunnelShared) -> String {
    loop {
        match reader.read(rd).await {
            Ok(None) => return "fermé par la maison".into(),
            Ok(Some(frame)) => {
                if let Err(reason) = shared.dispatch(frame).await {
                    return reason;
                }
            }
            Err(WireError::Frame(e)) => {
                let reason = format!("faute de protocole : {e}");
                shared.goaway(GoAwayCode::ProtocolError, &reason);
                return reason;
            }
            Err(WireError::Io(e)) => return format!("erreur de lecture : {}", e.kind()),
        }
    }
}

/// Coupe le tunnel à l'expiration du jeton en vigueur ; un `RENEW` accepté la repousse.
async fn expiry(shared: &TunnelShared) -> String {
    loop {
        let (expires_at, now) = (shared.expires_at.load(Ordering::Relaxed), relay_common::time::now_unix());
        if now >= expires_at {
            shared.goaway(GoAwayCode::TokenExpired, "jeton de tunnel expiré, en obtenir un neuf");
            return "jeton expiré".to_owned();
        }
        tokio::time::sleep(Duration::from_secs(u64::try_from(expires_at - now).unwrap_or(0))).await;
    }
}

async fn ping_loop(shared: &TunnelShared, interval: Duration) -> String {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if shared.missed_pings.load(Ordering::Relaxed) >= MAX_MISSED_PINGS {
            return format!("{MAX_MISSED_PINGS} pings sans réponse");
        }
        shared.missed_pings.fetch_add(1, Ordering::Relaxed);
        // Millisecondes Unix sur l'horloge du relais, rendues telles quelles par le `PONG`.
        let ts = relay_common::time::now_unix_millis();
        if shared.out.send(Frame::Ping { ts }).await.is_err() {
            return "file d'écriture fermée".into();
        }
    }
}

async fn write_loop<W: AsyncWrite>(
    wr: W,
    mut rx: mpsc::Receiver<Frame>,
    cancel: CancellationToken,
    timeout: Duration,
) {
    tokio::pin!(wr);
    let mut buf = Vec::with_capacity(WRITE_BATCH);
    loop {
        let frame = tokio::select! {
            biased;
            frame = rx.recv() => frame,
            () = cancel.cancelled() => None,
        };
        let Some(frame) = frame else { break };
        buf.clear();
        encode(&frame, &mut buf);
        while buf.len() < WRITE_BATCH {
            let Ok(frame) = rx.try_recv() else { break };
            encode(&frame, &mut buf);
        }
        match tokio::time::timeout(timeout, wr.write_all(&buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                cancel.cancel();
                return;
            }
        }
    }
    // Vidange de ce qui reste (le `GOAWAY` en particulier), puis fermeture.
    buf.clear();
    while let Ok(frame) = rx.try_recv() {
        encode(&frame, &mut buf);
    }
    let _ = tokio::time::timeout(timeout, async {
        let _ = wr.write_all(&buf).await;
        let _ = wr.shutdown().await;
    })
    .await;
}

fn encode(frame: &Frame, buf: &mut Vec<u8>) {
    if let Err(e) = frame.encode(buf) {
        // Trames construites par le relais : ne devrait pas arriver.
        tracing::error!(erreur = %e, type_trame = ?frame.kind(), "trame impossible à encoder, ignorée");
    }
}
