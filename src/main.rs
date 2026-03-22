mod cache;
mod config;
mod error;
mod middleware;
mod proxy;
mod registry;
mod server;

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(about, version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .with_target(true)
        .with_thread_ids(false)
        .init();

    tracing::info!("proxistry v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let app_config = config::AppConfig::load(&args.config)?;
    let listen_addr = app_config.server.listen.clone();

    tracing::info!(
        listen = %listen_addr,
        cache_dir = %app_config.cache.data_dir.display(),
        registries = %app_config.registries.len(),
        whitelist = %if app_config.whitelist.enabled {
            app_config.whitelist.registries.join(",")
        } else {
            "disabled".to_string()
        },
        "starting server"
    );

    // Build router and state
    let (app, state) = server::build_router(app_config).await?;

    // Spawn background tasks
    server::spawn_background_tasks(state);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("listening on {}", listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server shut down");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
