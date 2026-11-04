//! Signal d'arrêt : SIGTERM (Docker, redéploiement) ou Ctrl-C.

/// Se résout au premier SIGTERM ou Ctrl-C.
pub async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => tracing::info!("SIGTERM reçu, arrêt"),
                    _ = tokio::signal::ctrl_c() => tracing::info!("Ctrl-C reçu, arrêt"),
                }
            }
            Err(error) => {
                tracing::warn!(%error, "écoute de SIGTERM impossible, seul Ctrl-C arrêtera le relais");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Ctrl-C reçu, arrêt");
    }
}
