//! Binaire `relay-push` : configuration par l'environnement, secrets lus dans les fichiers
//! montés, serveur HTTP, arrêt propre sur SIGTERM.

use std::{process::ExitCode, sync::Arc, time::Duration};

use relay_common::config::Env;
use relay_push::{
    apns::{self, ApnsClient, ApnsConfig},
    app::{PushState, router},
    config::PushConfig,
    fcm::{self, FcmClient},
};
use tokio::net::TcpListener;

/// Erreur de démarrage : message sans secret.
type Fatal = String;

fn http_client() -> Result<reqwest::Client, Fatal> {
    reqwest::Client::builder()
        .user_agent(concat!("agendo-relay-push/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_while_idle(true)
        .build()
        .map_err(|e| format!("client HTTP : {e}"))
}

/// Lit un fichier de secret ; l'erreur cite le chemin, jamais le contenu.
fn read_secret(path: &std::path::Path) -> Result<String, Fatal> {
    std::fs::read_to_string(path).map_err(|e| format!("lecture de {} impossible : {}", path.display(), e.kind()))
}

fn state(config: &PushConfig) -> Result<PushState, Fatal> {
    let http = http_client()?;
    let apns = match &config.apns {
        None => None,
        Some(s) => {
            let key = apns::parse_p8(&read_secret(&s.key_file)?).map_err(|e| format!("{} : {e}", s.key_file.display()))?;
            let apns_config = ApnsConfig {
                key,
                key_id: s.key_id.clone(),
                team_id: s.team_id.clone(),
                topic: s.topic.clone(),
                base_url: s.base_url.clone(),
            };
            Some(ApnsClient::new(apns_config, http.clone()))
        }
    };
    let fcm = match &config.fcm {
        None => None,
        Some(s) => {
            let file = &s.service_account_file;
            let account = fcm::parse_service_account(&read_secret(file)?).map_err(|e| format!("{} : {e}", file.display()))?;
            Some(FcmClient::new(account, s.base_url.clone(), http.clone()))
        }
    };
    Ok(PushState::new(config.trusted_keys.clone(), apns, fcm, config.limits.clone()))
}

#[tokio::main]
async fn main() -> ExitCode {
    relay_common::logs::init("relay-push");
    let config = match PushConfig::from_env(&Env::from_os()) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "configuration invalide");
            return ExitCode::FAILURE;
        }
    };
    let state = match state(&config) {
        Ok(state) => Arc::new(state),
        Err(error) => {
            tracing::error!(%error, "démarrage impossible");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(config.addr).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(addr = %config.addr, %error, "écoute impossible");
            return ExitCode::FAILURE;
        }
    };
    // Arrêt des tâches annexes (métriques).
    let stop = Arc::new(tokio::sync::Notify::new());
    if let Some(addr) = config.metrics_addr {
        match TcpListener::bind(addr).await {
            Ok(m) => {
                let stopped = stop.clone();
                tokio::spawn(relay_common::metrics::serve(m, state.metrics.registry.clone(), async move { stopped.notified().await }));
            }
            Err(error) => {
                tracing::error!(%addr, %error, "écoute des métriques impossible");
                return ExitCode::FAILURE;
            }
        }
    }
    tracing::info!(
        addr = %config.addr,
        apns = config.apns.is_some(),
        fcm = config.fcm.is_some(),
        "relais push à l'écoute"
    );
    let served = axum::serve(listener, router(state)).with_graceful_shutdown(relay_common::shutdown::signal()).await;
    stop.notify_waiters();
    match served {
        Ok(()) => {
            tracing::info!("relais push arrêté");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "serveur HTTP arrêté sur erreur");
            ExitCode::FAILURE
        }
    }
}
