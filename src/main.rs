#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(target_env = "msvc")]
use mimalloc::MiMalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(all(not(target_env = "msvc"), not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(all(target_env = "msvc", not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use anyhow::Result;

use tokio::sync::watch;

use server::ServerManager;
use std::sync::Arc;
use std::{cmp::max, env, time::Instant};
use tracing::{error, info};

use chrono::Local;
use tracing_appender::rolling;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod authenticate;
mod config;
mod net;
mod processor;
mod protocol;
mod server;

fn init_logger() {
    #[derive(Clone, Copy, Default)]
    struct LocalTime;

    impl FormatTime for LocalTime {
        fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S%:z");
            write!(w, "{}", ts)
        }
    }

    // Ensure log directory exists. Prefer a `logs` folder next to the executable
    // so service/systemd runs with different working directories still write logs.
    let log_dir = std::env::current_exe()
        .ok()
        .and_then(|mut p| {
            p.pop();
            p.push("logs");
            Some(p)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("logs"));

    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("Failed to create log directory {:?}: {}", log_dir, e);
    }

    let file_appender = rolling::daily(log_dir, "iway.log");

    let file_layer = fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false)
        .with_target(false)
        .with_level(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_timer(LocalTime)
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);

    #[cfg(debug_assertions)]
    let console_layer = fmt::layer()
        .with_target(false)
        .with_line_number(true)
        .pretty()
        .with_timer(LocalTime)
        .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG);

    #[cfg(not(debug_assertions))]
    let console_layer = fmt::layer()
        .with_target(false)
        .with_line_number(true)
        .pretty()
        .with_timer(LocalTime)
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
    tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .init();
}

fn recommended_worker_threads(cpu_load_ratio: f64) -> usize {
    let cpus = num_cpus::get();
    max(1, (cpus as f64 * cpu_load_ratio).round() as usize)
}

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

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
async fn async_main() -> Result<(), String> {
    let start_time = Instant::now();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));
    let config = config::Config::from_file(config_path).unwrap_or_else(|e| {
        info!("Using default config: {}", e);
        let default_config = config::Config::default();
        if let Err(e) = default_config.save_to_file("config.toml") {
            error!("Failed to save default config: {}", e);
        }
        default_config
    });

    let config = Arc::new(config);

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let server_manager = ServerManager::new_with_config(Arc::clone(&config), Some(shutdown_rx));

    match server_manager.init().await {
        Ok(_) => info!(
            "ServerManager: Servers initialized in {:?}",
            start_time.elapsed()
        ),
        Err(e) => {
            error!("Failed to initialize servers: {}", e);
            return Err("Failed to initialize servers!".into());
        }
    }

    match server_manager.start().await {
        Ok(_) => info!(
            "ServerManager: Servers started in {:?}",
            start_time.elapsed()
        ),
        Err(e) => {
            error!("Failed to start servers: {}", e);
            return Err("Failed to start servers!".into());
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
