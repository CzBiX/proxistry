use http::header;
use reqwest::header::{AUTHORIZATION, HeaderMap, USER_AGENT};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::config::{AppConfig, RegistryConfig};
use crate::error::{AppError, AppResult};
use crate::registry::auth::AuthManager;

/// HTTP client for communicating with upstream registries.
#[allow(dead_code)]
pub struct UpstreamClient {
    /// Per-registry HTTP clients (with registry-specific TLS/UA config)
    clients: Mutex<HashMap<String, Client>>,
    /// Auth manager for token exchange
    auth_manager: Arc<AuthManager>,
    /// Per-registry concurrency limiters
    semaphores: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// App config
    config: Arc<AppConfig>,
}

impl UpstreamClient {
    pub fn new(config: Arc<AppConfig>, auth_manager: Arc<AuthManager>) -> AppResult<Self> {
        let mut clients = HashMap::new();
        let mut semaphores = HashMap::new();

        for reg in &config.registries {
            let client = build_client(reg)?;
            clients.insert(reg.name.clone(), client);
            semaphores.insert(
                reg.name.clone(),
                Arc::new(Semaphore::new(config.server.concurrent)),
            );
        }

        Ok(Self {
            clients: Mutex::new(clients),
            auth_manager,
            semaphores: Mutex::new(semaphores),
            config,
        })
    }

    /// Get or create an HTTP client for the given registry.
    async fn get_or_create_client(&self, registry: &RegistryConfig) -> AppResult<Client> {
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(&registry.name) {
            return Ok(client.clone());
        }

        // Create a new client for this unconfigured registry
        tracing::debug!(registry = %registry.name, "creating HTTP client for unconfigured registry");
        let client = build_client(registry)?;
        clients.insert(registry.name.clone(), client.clone());

        // Also create a semaphore for it
        let mut semaphores = self.semaphores.lock().await;
        semaphores.insert(
            registry.name.clone(),
            Arc::new(Semaphore::new(self.config.server.concurrent)),
        );

        Ok(client)
    }

    /// Send a request to an upstream registry, handling auth automatically.
    /// Retries once on 401 with a fresh token (safe for buffered bodies).
    pub async fn request(
        &self,
        registry: &RegistryConfig,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<impl Into<reqwest::Body>>,
    ) -> AppResult<Response> {
        let (client, mut req, _permit) = self
            .prepare_request(registry, method.clone(), url, &headers)
            .await?;

        let has_body = body.is_some();
        if let Some(body) = body {
            req = req.body(body);
        }
        let resp = req.send().await?;

        // Handle 401 - try token exchange
        if resp.status() == StatusCode::UNAUTHORIZED {
            if has_body {
                return Err(AppError::Internal(
                    "cannot retry request with body after 401".to_string(),
                ));
            }

            let resp_headers = resp.headers().clone();
            if let Some(auth_header) = self
                .auth_manager
                .handle_challenge(&registry.name, registry.auth.as_ref(), &resp_headers)
                .await?
            {
                // Retry with new token
                let mut retry_req = self.apply_common_request_parts(
                    client.request(method, url),
                    registry,
                    &headers,
                );
                retry_req = retry_req.header(AUTHORIZATION, auth_header);

                return Ok(retry_req.send().await?);
            }
        }

        Ok(resp)
    }

    /// Shared setup: get/create client, acquire semaphore, build request with
    /// common headers and auth. Returns (client, request_builder, permit).
    async fn prepare_request(
        &self,
        registry: &RegistryConfig,
        method: Method,
        url: &str,
        headers: &HeaderMap,
    ) -> AppResult<(
        Client,
        reqwest::RequestBuilder,
        Option<tokio::sync::OwnedSemaphorePermit>,
    )> {
        let client = self.get_or_create_client(registry).await?;

        let permit = {
            let semaphores = self.semaphores.lock().await;
            match semaphores.get(&registry.name).cloned() {
                Some(sem) => Some(
                    sem.acquire_owned()
                        .await
                        .map_err(|e| AppError::Internal(format!("semaphore error: {}", e)))?,
                ),
                None => None,
            }
        };

        let mut req =
            self.apply_common_request_parts(client.request(method, url), registry, headers);

        // Add auth header
        if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
            req = req.header(AUTHORIZATION, auth_header);
        } else if let Some(auth_header) = self
            .auth_manager
            .get_auth_header(&registry.name, registry.auth.as_ref())
            .await?
        {
            req = req.header(AUTHORIZATION, auth_header);
        }

        Ok((client, req, permit))
    }

    fn apply_common_request_parts(
        &self,
        req: reqwest::RequestBuilder,
        registry: &RegistryConfig,
        headers: &HeaderMap,
    ) -> reqwest::RequestBuilder {
        let req = Self::forward_relevant_headers(req, headers);
        Self::apply_user_agent(req, registry)
    }

    fn forward_relevant_headers(
        mut req: reqwest::RequestBuilder,
        headers: &HeaderMap,
    ) -> reqwest::RequestBuilder {
        for (key, value) in headers.iter() {
            if key == header::ACCEPT
                || key == header::CONTENT_TYPE
                || key == header::IF_NONE_MATCH
                || key == header::RANGE
            {
                req = req.header(key, value);
            }
        }

        req
    }

    fn apply_user_agent(
        req: reqwest::RequestBuilder,
        registry: &RegistryConfig,
    ) -> reqwest::RequestBuilder {
        if let Some(ref ua) = registry.user_agent {
            req.header(USER_AGENT, ua.as_str())
        } else {
            req.header(USER_AGENT, "proxistry/0.1")
        }
    }
}

fn build_client(registry: &RegistryConfig) -> AppResult<Client> {
    let mut builder = Client::builder();

    let tls = &registry.tls;
    if tls.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(ref ca_cert_path) = tls.ca_cert {
        let cert_data = std::fs::read(ca_cert_path).map_err(|e| {
            AppError::Config(format!(
                "failed to read CA cert {}: {}",
                ca_cert_path.display(),
                e
            ))
        })?;
        let cert = reqwest::Certificate::from_pem(&cert_data)
            .map_err(|e| AppError::Config(format!("invalid CA cert: {}", e)))?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|e| AppError::Config(format!("failed to build HTTP client: {}", e)))
}
