//! Métriques du relais push : requêtes par statut, erreurs des services par plateforme.

use relay_common::metrics::{Counter, Registry};

#[derive(Debug, Clone)]
pub struct PushMetrics {
    pub registry: Registry,
    pub sent: Counter,
    pub unregistered: Counter,
    pub rejected: Counter,
    pub quota: Counter,
    pub unavailable: Counter,
    pub upstream_ios: Counter,
    pub upstream_android: Counter,
}

impl PushMetrics {
    pub fn new() -> Self {
        let r = Registry::new();
        let requests = "Requêtes POST /v1/push, par statut rendu.";
        let upstream = "Erreurs d'APNs ou de FCM (indisponible, identifiants refusés), par plateforme.";
        Self {
            sent: r.counter("relay_push_requests_total", requests, &[("status", "sent")]),
            unregistered: r.counter("relay_push_requests_total", requests, &[("status", "unregistered")]),
            rejected: r.counter("relay_push_requests_total", requests, &[("status", "rejected")]),
            quota: r.counter("relay_push_requests_total", requests, &[("status", "quota")]),
            unavailable: r.counter("relay_push_requests_total", requests, &[("status", "unavailable")]),
            upstream_ios: r.counter("relay_push_upstream_errors_total", upstream, &[("platform", "ios")]),
            upstream_android: r.counter("relay_push_upstream_errors_total", upstream, &[("platform", "android")]),
            registry: r,
        }
    }
}

impl Default for PushMetrics {
    fn default() -> Self {
        Self::new()
    }
}
