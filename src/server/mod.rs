use std::{collections::HashMap, sync::Arc, time::Instant};

use anyhow::Error;
use async_trait::async_trait;
use tokio::sync::{Mutex, watch::Receiver};
use tracing::{error, info};
use tuic::TuicServer;

mod tuic;

#[async_trait]
pub trait Server: Send + Sync {
    fn name(&self) -> &'static str;

    async fn init(&mut self) -> Result<Instant, Error>;

    async fn start(&mut self) -> Result<Instant, Error>;

    async fn stop(&mut self) -> Result<Instant, Error>;

    async fn status(&mut self) -> Result<&ServerStatus, Error>;
}

pub struct ServerManager {
    servers: HashMap<String, Arc<Mutex<dyn Server>>>,
}

impl ServerManager {
    pub fn new_with_config(
        config: crate::config::Config,
        shutdown_rx: Option<Receiver<()>>,
    ) -> Self {
        let mut servers: HashMap<String, Arc<Mutex<dyn Server>>> = HashMap::new();

        let tuic_server = match TuicServer::new_with_config(config, shutdown_rx) {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to create TuicServer: {}", e);
                return Self { servers };
            }
        };

        servers.insert("Tuic".to_string(), Arc::new(Mutex::new(tuic_server)));

        Self { servers }
    }

    pub async fn init(&self) -> Result<Instant, Error> {
        for (_, server) in &self.servers {
            let mut server = server.lock().await;

            match server.init().await {
                Ok(_) => {
                    info!("Server {} initialized successfully", server.name());
                }
                Err(e) => {
                    error!("Failed to initialize server {}: {}", server.name(), e);
                }
            }
        }
        info!("ServerManager: Servers are initialized");
        Ok(Instant::now())
    }

    pub async fn start(&self) -> Result<Instant, Error> {
        for (_name, server) in self.servers.iter() {
            let server = Arc::clone(&server);
            tokio::spawn({
                async move {
                    let mut server = server.lock().await;
                    let _ = server.start().await;
                }
            });
        }

        Ok(Instant::now())
    }

    pub async fn stop(&self) -> Result<Instant, Error> {
        for (name, server) in self.servers.iter() {
            let server = Arc::clone(&server);
            let name = name.clone();
            let _handle = tokio::spawn({
                async move {
                    let mut server = server.lock().await;
                    match server.stop().await {
                        Ok(instant) => {
                            info!("Server {} stopped successfully", name);
                            Ok(instant)
                        }
                        Err(e) => {
                            error!("Failed to stop server {}: {}", name, e);
                            Err(e)
                        }
                    }
                }
            })
            .await;
        }

        Ok(Instant::now())
    }
}

#[derive(Debug, PartialEq)]
pub enum ServerStatus {
    Initializing(Instant),
    Running(Instant),
    Stopped(Instant),
}
