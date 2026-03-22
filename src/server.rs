use axum::routing::{any, get};
use axum::{Router, middleware};
use std::sync::Arc;
use std::time::Duration;

use crate::cache::manager::CacheManager;
use crate::cache::storage::FsStorage;
use crate::config::AppConfig;
use crate::error::AppResult;
use crate::middleware::logging::logging_middleware;
use crate::proxy::client::UpstreamClient;
use crate::proxy::handler;
use crate::registry::auth::AuthManager;

/// Shared application state.
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub cache: Arc<CacheManager>,
    pub upstream_client: Arc<UpstreamClient>,
    pub base_url: String,
}

/// Build the Axum router with all routes and middleware.
pub async fn build_router(config: AppConfig) -> AppResult<(Router, Arc<AppState>)> {
    let config = Arc::new(config);

    // Initialize storage backend
    let storage = Arc::new(FsStorage::new(config.cache.data_dir.clone()).await?)
        as Arc<dyn crate::cache::storage::StorageBackend>;

    // Initialize cache manager
    let cache = Arc::new(CacheManager::new(storage, config.clone()));

    // Initialize auth manager
    let auth_manager = Arc::new(AuthManager::new());

    // Initialize upstream client
    let upstream_client = Arc::new(UpstreamClient::new(config.clone(), auth_manager)?);

    // Determine base URL: use configured value or fall back to http://{listen}
    let base_url = config
        .server
        .base_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", config.server.listen));

    let state = Arc::new(AppState {
        config: config.clone(),
        cache,
        upstream_client,
        base_url,
    });

    let app = Router::new()
        // V2 base endpoint
        .route("/v2/", get(handler::v2_base))
        .route("/_/stats", get(stats_handler))
        .route("/_/health", get(health_handler))
        // Catch-all for registry API requests
        .route("/v2/{*path}", any(handler::proxy_handler))
        .with_state(state.clone())
        .layer(middleware::from_fn(logging_middleware));

    Ok((app, state))
}

/// Spawn background tasks (LRU eviction, cleanup).
pub fn spawn_background_tasks(state: Arc<AppState>) {
    let eviction_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // every 5 minutes
        loop {
            interval.tick().await;
            match eviction_state.cache.run_eviction().await {
                Ok(freed) => {
                    if freed > 0 {
                        tracing::info!(freed_bytes = %freed, "background eviction completed");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "background eviction failed");
                }
            }
        }
    });
}

/// GET /_/stats — cache statistics.
async fn stats_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    let total_size = state.cache.total_size().await.unwrap_or(0);
    let hits = state.cache.stats.hit_count();
    let misses = state.cache.stats.miss_count();
    let total = hits + misses;
    let hit_rate = if total > 0 {
        (hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let stats = serde_json::json!({
        "cache": {
            "hits": hits,
            "misses": misses,
            "hit_rate_percent": format!("{:.1}", hit_rate),
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "max_size_gb": state.config.cache.max_size_gb,
        }
    });

    axum::Json(stats)
}

/// GET /_/health — simple health check.
async fn health_handler() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}
