//! Port public : une connexion d'un navigateur ou de l'app vers une maison.
//!
//! 1. Pair TCP autorisé à parler PROXY protocol, puis en-tête v2 : l'adresse réelle du client.
//! 2. Limite de connexions par IP du client.
//! 3. ClientHello lu (borné en taille et en temps) : nom demandé.
//! 4. Maison qui sert ce nom : `OPEN`, puis les octets déjà lus rejoués en `DATA`, puis recopie
//!    dans les deux sens, sans rien déchiffrer.
//!
//! Nom inconnu, maison absente, en-tête ou ClientHello invalides : fermeture, sans réponse.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use agendo_access_protocol::frame::{CloseCode, MAX_PAYLOAD};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use crate::{
    client_hello::{HelloError, MAX_HELLO_BYTES, peek_sni},
    config::ProxyPolicy,
    proxy_protocol,
    server::RelayState,
    tunnel::StreamHandle,
};

/// Taille des lectures côté client.
const CHUNK: usize = 16 * 1024;

/// Sert une connexion du port public.
pub async fn handle(mut tcp: TcpStream, peer: SocketAddr, relay: Arc<RelayState>) {
    let limits = &relay.config.limits;
    let metrics = &relay.metrics;
    let deadline = Instant::now() + limits.hello_timeout;
    let client = match &relay.config.proxy {
        ProxyPolicy::Off => peer,
        policy @ ProxyPolicy::Required(_) => {
            if !policy.allows_peer(peer.ip()) {
                metrics.public_proxy_refused.inc();
                tracing::warn!(pair = %peer.ip(), "connexion publique d'un pair non autorisé à envoyer l'en-tête PROXY, fermée");
                return;
            }
            match proxy_protocol::read_header(&mut tcp, deadline.saturating_duration_since(Instant::now())).await {
                Ok(header) => header.source,
                Err(error) => {
                    metrics.public_proxy_refused.inc();
                    tracing::debug!(pair = %peer.ip(), %error, "en-tête PROXY refusé");
                    return;
                }
            }
        }
    };
    let Some(_guard) = relay.public_limiter.try_acquire(client.ip()) else {
        metrics.public_limited.inc();
        tracing::debug!(ip = %client.ip(), "trop de connexions de cette IP, fermée");
        return;
    };
    let (host, hello) = match tokio::time::timeout_at(deadline, read_client_hello(&mut tcp)).await {
        Ok(Ok(found)) => found,
        Ok(Err(error)) => {
            metrics.public_bad_hello.inc();
            tracing::debug!(ip = %client.ip(), %error, "début de connexion illisible");
            return;
        }
        Err(_) => {
            metrics.public_bad_hello.inc();
            tracing::debug!(ip = %client.ip(), "ClientHello trop lent");
            return;
        }
    };
    let Some(tunnel) = relay.registry.get(&host) else {
        metrics.public_unknown_host.inc();
        tracing::debug!(ip = %client.ip(), hote = %host, "aucune maison connectée ne sert ce nom");
        return;
    };
    let stream = match tunnel.open_stream(client).await {
        Ok(stream) => stream,
        Err(error) => {
            metrics.public_limited.inc();
            tracing::info!(ip = %client.ip(), maison = %tunnel.house(), %error, "flux refusé");
            return;
        }
    };
    metrics.public_routed.inc();
    let _ = tcp.set_nodelay(true);
    pipe(tcp, stream, hello, limits.write_timeout, limits.idle_timeout).await;
}

/// Erreur de lecture du ClientHello.
#[derive(Debug, thiserror::Error)]
enum ReadError {
    #[error(transparent)]
    Hello(#[from] HelloError),
    #[error("connexion fermée avant la fin du ClientHello")]
    Closed,
    #[error("erreur de lecture : {0}")]
    Io(std::io::ErrorKind),
}

/// Lit jusqu'à avoir le ClientHello entier ; rend le nom demandé et les octets lus.
async fn read_client_hello(tcp: &mut TcpStream) -> Result<(String, Vec<u8>), ReadError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 4096];
    loop {
        let room = MAX_HELLO_BYTES.saturating_sub(buf.len()).min(chunk.len());
        let n = tcp.read(chunk.get_mut(..room).unwrap_or_default()).await.map_err(|e| ReadError::Io(e.kind()))?;
        if n == 0 {
            return Err(ReadError::Closed);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        if let Some(host) = peek_sni(&buf)? {
            return Ok((host, buf));
        }
    }
}

/// Fin de la recopie.
enum Outcome {
    /// Le client a fermé (ou erreur de son côté) : `CLOSE` à la maison.
    Client(CloseCode),
    /// La maison a fermé, ou le tunnel est tombé.
    House,
    /// Rien dans aucun sens depuis trop longtemps.
    Idle,
}

async fn pipe(tcp: TcpStream, stream: StreamHandle, hello: Vec<u8>, write_timeout: Duration, idle_timeout: Duration) {
    // Octets déjà lus : rejoués d'abord, dans la limite du crédit.
    let mut rest = hello.as_slice();
    while !rest.is_empty() {
        let Some(credit) = stream.credit().await else { return };
        let (head, tail) = rest.split_at(credit.min(rest.len()).min(MAX_PAYLOAD));
        if !stream.send(head.to_vec()).await {
            return;
        }
        rest = tail;
    }
    let (mut rd, mut wr) = tcp.into_split();
    let started = std::time::Instant::now();
    let last = AtomicU64::new(0);
    let touch = || last.store(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
    let outcome = {
        let upload = async {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let Some(credit) = stream.credit().await else { return Outcome::House };
                let room = credit.min(CHUNK);
                let n = match rd.read(buf.get_mut(..room).unwrap_or_default()).await {
                    Ok(0) => return Outcome::Client(CloseCode::Normal),
                    Ok(n) => n,
                    Err(_) => return Outcome::Client(CloseCode::Error),
                };
                touch();
                if !stream.send(buf.get(..n).unwrap_or_default().to_vec()).await {
                    return Outcome::House;
                }
            }
        };
        let download = async {
            while let Some(data) = stream.recv().await {
                match tokio::time::timeout(write_timeout, wr.write_all(&data)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return Outcome::Client(CloseCode::Error),
                    Err(_) => return Outcome::Client(CloseCode::Timeout),
                }
                touch();
                stream.release(data.len()).await;
            }
            let _ = wr.shutdown().await;
            Outcome::House
        };
        let idle = async {
            let check = (idle_timeout / 4).max(Duration::from_millis(100));
            loop {
                tokio::time::sleep(check).await;
                let now = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let idle_ms = u64::try_from(idle_timeout.as_millis()).unwrap_or(u64::MAX);
                if now.saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms {
                    return Outcome::Idle;
                }
            }
        };
        tokio::select! {
            outcome = upload => outcome,
            outcome = download => outcome,
            outcome = idle => outcome,
        }
    };
    match outcome {
        Outcome::Client(code) => stream.close(code).await,
        Outcome::Idle => stream.close(CloseCode::Timeout).await,
        Outcome::House => drop(stream),
    }
}
