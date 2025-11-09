#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(target_env = "msvc")]
use mimalloc::MiMalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(target_env = "msvc")]
#[global_allocator]
static GLOBAL: Mimalloc = Mimalloc;

use anyhow::Result;

use tokio::sync::watch;

use server::ServerManager;
use std::{cmp::max, env, time::Instant};
use tracing::{error, info};

use tracing_appender::rolling;
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod authenticate;
mod config;
mod processor;
mod protocol;
mod server;

fn init_logger() {
    // 1️⃣ 文件轮转：按天滚动日志（logs/iway.log）
    let file_appender = rolling::daily("logs", "iway.log");

    // 2️⃣ 文件日志层
    let file_layer = fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false) // 文件中不使用彩色
        .with_target(false)
        .with_level(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);

    // 3️⃣ 控制台日志层
    #[cfg(debug_assertions)]
    let console_layer = fmt::layer()
        .with_target(false)
        .with_line_number(true)
        .pretty()
        .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG);

    #[cfg(not(debug_assertions))]
    let console_layer = fmt::layer()
        .with_target(false)
        .with_line_number(true)
        .pretty()
        .with_filter(tracing_subscriber::filter::LevelFilter::WARN);
    // 4️⃣ 组合两个层
    tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .init();
}

fn recommended_worker_threads(cpu_load_ratio: f64) -> usize {
    let cpus = num_cpus::get();
    max(2, (cpus as f64 * cpu_load_ratio).round() as usize)
}

fn main() {
    init_logger();

    let num_threads = recommended_worker_threads(1.0);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_threads)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to build tokio runtime: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = runtime.block_on(async_main()) {
        error!("Application error: {}", e);
        std::process::exit(1);
    }
}

// #[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn async_main() -> Result<()> {
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

    let stop_time = Instant::now();

    let _ = shutdown_tx.send(());

    info!("Received shutdown signal, stopping servers...");
    let _ = server_manager.stop().await;

    info!(
        "ServerManager: Servers stopped in {:?}",
        stop_time.elapsed()
    );

    Ok(())
}

async fn setup_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install SIGTERM handler: {}", e);
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install SIGINT handler: {}", e);
                return;
            }
        };

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

        let mut ctrl_c = match windows::ctrl_c() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install Ctrl+C handler: {}", e);
                return;
            }
        };
        let mut ctrl_break = match windows::ctrl_break() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install Ctrl+Break handler: {}", e);
                return;
            }
        };

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
