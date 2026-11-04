//! Métriques du relais SNI. Aucune étiquette ne porte de nom d'hôte ni d'IP.

use relay_common::metrics::{Counter, Gauge, Registry};

/// Compteurs et jauges du relais SNI.
#[derive(Debug, Clone)]
pub struct SniMetrics {
    pub registry: Registry,
    /// Tunnels ouverts (maisons connectées).
    pub tunnels: Gauge,
    /// Flux ouverts, tous tunnels confondus.
    pub streams: Gauge,
    pub handshakes_accepted: Counter,
    pub handshakes_refused: Counter,
    pub handshakes_failed: Counter,
    pub tunnels_replaced: Counter,
    pub public_routed: Counter,
    pub public_unknown_host: Counter,
    pub public_bad_hello: Counter,
    pub public_proxy_refused: Counter,
    pub public_limited: Counter,
    pub bytes_to_house: Counter,
    pub bytes_to_client: Counter,
}

impl SniMetrics {
    pub fn new() -> Self {
        let r = Registry::new();
        let handshakes = "Poignées de main des tunnels, par issue.";
        let public = "Connexions du port public, par issue.";
        let bytes = "Octets recopiés, par sens.";
        Self {
            tunnels: r.gauge("relay_sni_tunnels", "Tunnels ouverts.", &[]),
            streams: r.gauge("relay_sni_streams", "Flux ouverts.", &[]),
            handshakes_accepted: r.counter("relay_sni_handshakes_total", handshakes, &[("result", "accepted")]),
            handshakes_refused: r.counter("relay_sni_handshakes_total", handshakes, &[("result", "refused")]),
            handshakes_failed: r.counter("relay_sni_handshakes_total", handshakes, &[("result", "failed")]),
            tunnels_replaced: r.counter("relay_sni_tunnels_replaced_total", "Tunnels remplacés par une connexion plus récente.", &[]),
            public_routed: r.counter("relay_sni_public_connections_total", public, &[("result", "routed")]),
            public_unknown_host: r.counter("relay_sni_public_connections_total", public, &[("result", "unknown_host")]),
            public_bad_hello: r.counter("relay_sni_public_connections_total", public, &[("result", "bad_hello")]),
            public_proxy_refused: r.counter("relay_sni_public_connections_total", public, &[("result", "proxy_refused")]),
            public_limited: r.counter("relay_sni_public_connections_total", public, &[("result", "limited")]),
            bytes_to_house: r.counter("relay_sni_bytes_total", bytes, &[("direction", "to_house")]),
            bytes_to_client: r.counter("relay_sni_bytes_total", bytes, &[("direction", "to_client")]),
            registry: r,
        }
    }
}

impl Default for SniMetrics {
    fn default() -> Self {
        Self::new()
    }
}
