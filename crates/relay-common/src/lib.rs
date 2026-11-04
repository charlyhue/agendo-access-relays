//! Commun aux relais d'**Agendo Access** (`relay-sni`, `relay-push`).
//!
//! | Module | Contenu |
//! |---|---|
//! | [`config`] | lecture des variables d'environnement, clés de confiance |
//! | [`logs`] | logs JSON en français, sans secret ni contenu |
//! | [`metrics`] | compteurs et jauges, exposés en texte Prometheus sur un port interne |
//! | [`limits`] | connexions simultanées par IP et au total |
//! | [`shutdown`] | signal d'arrêt (SIGTERM, Ctrl-C) |
//! | [`time`] | heure Unix |

pub mod config;
pub mod limits;
pub mod logs;
pub mod metrics;
pub mod shutdown;
pub mod time;
