//! Octets quelconques envoyés par une maison **authentifiée**, rejoués dans un vrai tunnel du
//! relais après `READY`, avec deux flux ouverts côté clients : multiplexeur, fenêtres, `CLOSE`,
//! `PING`, `RENEW`, trames inattendues. Le relais ne doit jamais paniquer, et le tunnel doit se
//! terminer (fin du flux de la maison). Temps virtuel : les délais passent sans attendre.
#![no_main]

use std::time::Duration;

use agendo_access_protocol::{keys::encode_public_key, token::TunnelClaims};
use libfuzzer_sys::fuzz_target;
use relay_sni::{
    config::Limits,
    metrics::SniMetrics,
    registry::Registry,
    testkit::{HOST, ZONE, house_key, trusted_keys},
    tunnel::{TunnelSetup, serve},
    wire::FrameReader,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fuzz_target!(|data: &[u8]| {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build() else { return };
    rt.block_on(async {
        let (house, relay_end) = tokio::io::duplex(1 << 20);
        let (registry, metrics, shutdown, keys) = (Registry::new(), SniMetrics::new(), CancellationToken::new(), trusted_keys());
        let limits = Limits { initial_window: 16 * 1024, ..Limits::default() };
        let now = relay_common::time::now_unix();
        let claims = TunnelClaims {
            iss: "https://api".into(),
            sub: "maison".into(),
            host: HOST.into(),
            house_key: encode_public_key(&house_key().verifying_key()),
            iat: now,
            exp: now + 3600,
        };
        let setup = TunnelSetup {
            id: 1,
            claims,
            nonce: [5; 32],
            keys: &keys,
            zone: ZONE,
            peer_ip: [198, 51, 100, 9].into(),
            limits: &limits,
            registry: &registry,
            metrics: &metrics,
            shutdown: &shutdown,
        };
        let relay = serve(relay_end, FrameReader::new(), setup);
        let house_side = async {
            // Le tunnel est inscrit dès le début de `serve` : deux clients ouvrent un flux.
            tokio::task::yield_now().await;
            let tunnel = registry.get(HOST);
            let mut streams = Vec::new();
            if let Some(tunnel) = &tunnel {
                for port in [1000u16, 1001] {
                    if let Ok(stream) = tunnel.open_stream(([203, 0, 113, 7], port).into()).await {
                        streams.push(stream);
                    }
                }
            }
            let (mut rd, mut wr) = tokio::io::split(house);
            let drain = async {
                let mut buf = vec![0u8; 64 * 1024];
                while matches!(rd.read(&mut buf).await, Ok(n) if n > 0) {}
            };
            let feed = async {
                let _ = wr.write_all(data).await;
                let _ = wr.shutdown().await;
            };
            // Les clients consomment ce que la maison leur envoie, et rendent du crédit.
            let clients = async {
                for stream in &streams {
                    while let Ok(Some(bytes)) = tokio::time::timeout(Duration::from_millis(1), stream.recv()).await {
                        stream.release(bytes.len()).await;
                    }
                }
            };
            tokio::join!(drain, feed, clients);
            drop(streams);
        };
        let finished = tokio::time::timeout(Duration::from_secs(3600), async { tokio::join!(relay, house_side) }).await;
        assert!(finished.is_ok(), "le tunnel ne s'est pas terminé");
        assert!(registry.is_empty(), "tunnel resté inscrit");
    });
});
