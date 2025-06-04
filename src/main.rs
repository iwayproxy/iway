use anyhow::Result;

#[cfg(debug_assertions)]
use console_subscriber::ConsoleLayer;
use tokio::sync::watch;
#[cfg(debug_assertions)]
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use log::{error, info};
use server::ServerManager;
use std::{env, time::Instant};

#[cfg(all(not(windows), not(target_env = "msvc")))]
use jemallocator;

mod authenticate;
mod config;
mod processor;
mod protocol;
mod server;

#[cfg(all(not(windows), not(target_env = "msvc")))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(debug_assertions)]
fn init_logging() {
    tracing_log::LogTracer::init().expect("log tracer init failed");

    let subscriber = tracing_subscriber::registry()
        .with(
            ConsoleLayer::builder()
                .retention(std::time::Duration::from_secs(60))
                .spawn(),
        )
        .with(fmt::layer().with_filter(EnvFilter::from_default_env()));

    tracing::subscriber::set_global_default(subscriber).expect("setting tracing default failed");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    init_logging();

    #[cfg(not(debug_assertions))]
    env_logger::init();

    let start_time = Instant::now();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = config::Config::from_file(config_path).unwrap_or_else(|e| {
        info!("Using default config: {}", e);
        let default_config = config::Config::default();
        if let Err(e) = default_config.save_to_file("config.toml") {
            error!("Failed to save default config: {}", e);
        }
        default_config
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let server_manager = ServerManager::new_with_config(config, Some(shutdown_rx));

    match server_manager.init().await {
        Ok(_) => info!(
            "ServerManager: Servers initialized in {:?}",
            start_time.elapsed()
        ),
        Err(e) => {
            error!("Failed to initialize servers: {}", e);
            std::process::exit(1);
        }
    }

    match server_manager.start().await {
        Ok(_) => info!(
            "ServerManager: Servers started in {:?}",
            start_time.elapsed()
        ),
        Err(e) => {
            error!("Failed to start servers: {}", e);
            std::process::exit(1);
        }
    }

    let shutdown = setup_shutdown_signal();
    shutdown.await;

    let _ = shutdown_tx.send(());

    info!("Received shutdown signal, stopping servers...");
    let _ = server_manager.stop().await;

    info!(
        "ServerManager: Servers stopped in {:?}",
        start_time.elapsed()
    );

    Ok(())
}

async fn setup_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();

        let _ = tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM signal, shutting down");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT signal, shutting down");
                }
            }
        })
        .await;
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows;

        let mut ctrl_c = windows::ctrl_c().unwrap();
        let mut ctrl_break = windows::ctrl_break().unwrap();

        let _ = tokio::spawn(async move {
            tokio::select! {
                _ = ctrl_c.recv() => {
                    info!("Received Ctrl+C signal, shutting down");
                }
                _ = ctrl_break.recv() => {
                    info!("Received Ctrl+Break signal, shutting down");
                }
            }
        })
        .await;
    }
}
