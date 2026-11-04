//! Logs JSON sur la sortie standard, en français.
//!
//! Règle des relais : **ni secret ni contenu** dans les logs. Jamais un jeton, une signature,
//! un jeton de téléphone, un chiffré ni les octets d'un flux. On journalise l'identifiant de
//! la maison (`sub`), son nom d'hôte, l'IP du client, des tailles, des durées et des statuts.

use tracing_subscriber::{EnvFilter, fmt};

/// Variable du filtre des logs (syntaxe `tracing_subscriber::EnvFilter`, défaut `info`).
pub const LOG_FILTER_VAR: &str = "RELAY_LOG";

/// Installe les logs JSON du service `service` (champ `service` de chaque ligne via la cible).
pub fn init(service: &'static str) {
    let filter = EnvFilter::try_from_env(LOG_FILTER_VAR).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .try_init();
    tracing::info!(service, version = env!("CARGO_PKG_VERSION"), "démarrage");
}
