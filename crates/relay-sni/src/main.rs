//! Binaire `relay-sni` : configuration par l'environnement, liaison des ports, arrêt sur
//! SIGTERM (`GOAWAY` 0 aux maisons).

use std::process::ExitCode;

use relay_common::config::Env;
use relay_sni::{
    config::SniConfig,
    server::{Listeners, Relay},
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    relay_common::logs::init("relay-sni");
    let config = match SniConfig::from_env(&Env::from_os()) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "configuration invalide");
            return ExitCode::FAILURE;
        }
    };
    let bind = |addr| async move { TcpListener::bind(addr).await.map_err(|error| (addr, error)) };
    let listeners = async {
        Ok::<_, (std::net::SocketAddr, std::io::Error)>(Listeners {
            public: bind(config.public_addr).await?,
            tunnels: bind(config.tunnel_addr).await?,
            metrics: match config.metrics_addr {
                Some(addr) => Some(bind(addr).await?),
                None => None,
            },
        })
    };
    let listeners = match listeners.await {
        Ok(listeners) => listeners,
        Err((addr, error)) => {
            tracing::error!(%addr, %error, "écoute impossible");
            return ExitCode::FAILURE;
        }
    };
    Relay::new(config).run(listeners, relay_common::shutdown::signal()).await;
    ExitCode::SUCCESS
}
