//! Le relais : boucles d'acceptation des deux ports, métriques, arrêt propre.

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use agendo_access_protocol::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, frame::GoAwayCode};
use relay_common::limits::IpLimiter;
use tokio::{net::TcpListener, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{ProxyPolicy, SniConfig},
    handshake::{HandshakeError, HandshakeParams, handshake},
    metrics::SniMetrics,
    proxy_protocol, public,
    registry::Registry,
    tunnel::{self, TunnelSetup},
    wire::FrameReader,
};

/// Écouteurs déjà liés (les tests lient des ports éphémères).
pub struct Listeners {
    pub public: TcpListener,
    pub tunnels: TcpListener,
    pub metrics: Option<TcpListener>,
}

/// État partagé du relais.
#[derive(Debug)]
pub struct RelayState {
    pub config: SniConfig,
    pub registry: Registry,
    pub metrics: SniMetrics,
    pub public_limiter: IpLimiter,
    pub tunnel_limiter: IpLimiter,
    next_tunnel: AtomicU64,
    shutdown: CancellationToken,
}

/// Le relais SNI.
#[derive(Debug, Clone)]
pub struct Relay {
    state: Arc<RelayState>,
}

impl Relay {
    pub fn new(config: SniConfig) -> Self {
        let l = &config.limits;
        let public_limiter = IpLimiter::new(l.max_connections_per_ip, l.max_connections);
        let tunnel_limiter = IpLimiter::new(l.max_tunnels_per_ip, l.max_tunnels);
        Self {
            state: Arc::new(RelayState {
                config,
                registry: Registry::new(),
                metrics: SniMetrics::new(),
                public_limiter,
                tunnel_limiter,
                next_tunnel: AtomicU64::new(1),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    pub fn metrics(&self) -> &SniMetrics {
        &self.state.metrics
    }

    /// Sert jusqu'à `shutdown`, puis envoie `GOAWAY` 0 à toutes les maisons et leur laisse le
    /// délai de grâce pour partir.
    pub async fn run(self, listeners: Listeners, shutdown: impl Future<Output = ()>) {
        let state = self.state;
        if let Some(listener) = listeners.metrics {
            let registry = state.metrics.registry.clone();
            tokio::spawn(relay_common::metrics::serve(listener, registry, state.shutdown.clone().cancelled_owned()));
        }
        tracing::info!(
            public = %listeners.public.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            tunnels = %listeners.tunnels.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            zone = %state.config.zone,
            proxy_protocol = matches!(state.config.proxy, ProxyPolicy::Required(_)),
            "relais SNI à l'écoute"
        );
        let public = accept_loop(listeners.public, "public", state.clone(), public::handle);
        let tunnels = accept_loop(listeners.tunnels, "tunnels", state.clone(), accept_tunnel);
        tokio::select! {
            () = shutdown => {}
            () = public => {}
            () = tunnels => {}
        }
        // Les écouteurs sont fermés : plus aucune connexion acceptée.
        let count = state.registry.len();
        tracing::info!(tunnels = count, "arrêt : GOAWAY aux maisons");
        state.shutdown.cancel();
        let deadline = Instant::now() + state.config.limits.shutdown_grace;
        while !state.registry.is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tracing::info!("relais SNI arrêté");
    }
}

async fn accept_loop<F, Fut>(listener: TcpListener, port: &'static str, state: Arc<RelayState>, handler: F)
where
    F: Fn(tokio::net::TcpStream, SocketAddr, Arc<RelayState>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                tokio::spawn(handler(tcp, peer, state.clone()));
            }
            Err(error) => {
                // Descripteurs épuisés, par exemple : ne pas boucler à vide.
                tracing::warn!(port, %error, "acceptation impossible");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Connexion d'une maison sur le port des tunnels.
async fn accept_tunnel(mut tcp: tokio::net::TcpStream, peer: SocketAddr, state: Arc<RelayState>) {
    let limits = &state.config.limits;
    let metrics = &state.metrics;
    let deadline = Instant::now() + limits.handshake_timeout;
    let house_addr = match &state.config.proxy {
        ProxyPolicy::Off => peer,
        policy @ ProxyPolicy::Required(_) => {
            if !policy.allows_peer(peer.ip()) {
                metrics.handshakes_failed.inc();
                tracing::warn!(pair = %peer.ip(), "tunnel d'un pair non autorisé à envoyer l'en-tête PROXY, fermé");
                return;
            }
            match proxy_protocol::read_header(&mut tcp, deadline.saturating_duration_since(Instant::now())).await {
                Ok(header) => header.source,
                Err(error) => {
                    metrics.handshakes_failed.inc();
                    tracing::debug!(pair = %peer.ip(), %error, "en-tête PROXY du tunnel refusé");
                    return;
                }
            }
        }
    };
    let Some(_guard) = state.tunnel_limiter.try_acquire(house_addr.ip()) else {
        metrics.handshakes_refused.inc();
        tracing::warn!(ip = %house_addr.ip(), "trop de tunnels de cette IP, fermé");
        return;
    };
    let _ = tcp.set_nodelay(true);
    let mut reader = FrameReader::new();
    let now = relay_common::time::now_unix();
    let params = HandshakeParams {
        keys: &state.config.trusted_keys,
        zone: &state.config.zone,
        versions: (MIN_PROTOCOL_VERSION, PROTOCOL_VERSION),
        initial_window: limits.initial_window,
        ping_interval: limits.ping_interval,
        timeout: deadline.saturating_duration_since(Instant::now()),
        now,
    };
    let accepted = match handshake(&mut tcp, &mut reader, &params).await {
        Ok(accepted) => accepted,
        Err(HandshakeError::Refused { code, reason }) => {
            metrics.handshakes_refused.inc();
            tracing::warn!(ip = %house_addr.ip(), code = ?code, raison = %reason, "tunnel refusé");
            return;
        }
        Err(error) => {
            metrics.handshakes_failed.inc();
            tracing::debug!(ip = %house_addr.ip(), %error, "poignée de main interrompue");
            return;
        }
    };
    metrics.handshakes_accepted.inc();
    if state.shutdown.is_cancelled() {
        let frame = agendo_access_protocol::frame::Frame::GoAway { code: GoAwayCode::Shutdown, message: "arrêt du relais".into() };
        let _ = crate::wire::write_frame(&mut tcp, &frame).await;
        return;
    }
    let setup = TunnelSetup {
        id: state.next_tunnel.fetch_add(1, Ordering::Relaxed),
        claims: accepted.claims,
        nonce: accepted.nonce,
        keys: &state.config.trusted_keys,
        zone: &state.config.zone,
        peer_ip: house_addr.ip(),
        limits,
        registry: &state.registry,
        metrics,
        shutdown: &state.shutdown,
    };
    tunnel::serve(tcp, reader, setup).await;
}
