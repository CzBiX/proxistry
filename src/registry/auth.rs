use std::collections::HashMap;

use base64::Engine;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use serde::Deserialize;

use crate::config::AuthConfig;
use crate::error::{AppError, AppResult};

/// A cached auth token with its expiry.
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: DateTime<Utc>,
}

/// Manages authentication for upstream registries.
pub struct AuthManager {
    token_cache: DashMap<String, CachedToken>,
    http_client: reqwest::Client,
}

fn urlencode(input: &str) -> String {
    utf8_percent_encode(input, NON_ALPHANUMERIC).to_string()
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            token_cache: DashMap::new(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Build a Bearer authorization header from a raw token string.
    fn bearer_header(token: &str) -> AppResult<HeaderValue> {
        HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|e| AppError::Auth(format!("invalid header value: {}", e)))
    }

    /// Return a cached bearer token header if one exists and hasn't expired.
    fn cached_token_header(&self, registry_name: &str) -> AppResult<Option<HeaderValue>> {
        if let Some(cached) = self.token_cache.get(registry_name) {
            if cached.expires_at > Utc::now() {
                tracing::debug!(registry = %registry_name, "using cached auth token");
                return Ok(Some(Self::bearer_header(&cached.token)?));
            }
            tracing::debug!(registry = %registry_name, "cached auth token expired");
        }
        Ok(None)
    }

    /// Get an authorization header value for a request.
    /// Returns None if no auth is configured.
    pub async fn get_auth_header(
        &self,
        registry_name: &str,
        auth_config: Option<&AuthConfig>,
    ) -> AppResult<Option<HeaderValue>> {
        // Check token cache first — a previously exchanged token takes priority
        if let Some(val) = self.cached_token_header(registry_name)? {
            return Ok(Some(val));
        }

        let auth_config = match auth_config {
            Some(c) => c,
            None => {
                tracing::debug!(registry = %registry_name, "no auth configured");
                return Ok(None);
            }
        };

        match auth_config {
            AuthConfig::Basic { username, password, .. } => {
                tracing::debug!(registry = %registry_name, username = %username, "using basic auth");
                let pass = if let Some(p) = password {
                    p.clone()
                } else {
                    String::new()
                };
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", username, pass));
                let val = HeaderValue::from_str(&format!("Basic {}", encoded))
                    .map_err(|e| AppError::Auth(format!("invalid header value: {}", e)))?;
                Ok(Some(val))
            }
            AuthConfig::Bearer { token, .. } => {
                tracing::debug!(registry = %registry_name, "using static bearer token");
                Ok(Some(Self::bearer_header(token)?))
            }
        }
    }

    /// Handle a 401 response by performing token exchange.
    /// Returns the new Authorization header if successful.
    pub async fn handle_challenge(
        &self,
        registry_name: &str,
        auth_config: Option<&AuthConfig>,
        response_headers: &HeaderMap,
    ) -> AppResult<Option<HeaderValue>> {
        let www_auth = match response_headers.get(WWW_AUTHENTICATE) {
            Some(v) => v.to_str().unwrap_or("").to_string(),
            None => {
                tracing::warn!(registry = %registry_name, "no WWW-Authenticate header in 401 response");
                return Ok(None);
            }
        };

        // Parse: Bearer realm="...",service="...",scope="..."
        if !www_auth.starts_with("Bearer ") {
            tracing::warn!(registry = %registry_name, "unsupported auth scheme in WWW-Authenticate");
            return Ok(None);
        }

        let params = parse_www_authenticate(&www_auth);
        let realm = params.get("realm").cloned().unwrap_or_default();
        let service = params.get("service").cloned().unwrap_or_default();
        let scope = params.get("scope").cloned().unwrap_or_default();

        tracing::info!(
            registry = %registry_name,
            realm = %realm,
            service = %service,
            scope = %scope,
            "received auth challenge"
        );

        if realm.is_empty() {
            return Err(AppError::Auth("empty realm in WWW-Authenticate".into()));
        }

        // Check token cache
        if let Some(val) = self.cached_token_header(registry_name)? {
            return Ok(Some(val));
        }

        // Perform token exchange
        let mut url = format!("{}?service={}", realm, urlencode(&service));
        if !scope.is_empty() {
            url.push_str(&format!("&scope={}", urlencode(&scope)));
        }

        tracing::debug!(registry = %registry_name, realm = %realm, "performing token exchange");

        let mut req = self.http_client.get(&url);

        // Add credentials if available
        if let Some(AuthConfig::Basic {
            username, password, ..
        }) = auth_config
            && let (user, Some(pass)) = (username, password)
        {
            tracing::debug!(registry = %registry_name, username = %user, "attaching basic credentials to token request");
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Auth(format!("token exchange failed: {}", e)))?;

        if !resp.status().is_success() {
            tracing::warn!(registry = %registry_name, status = %resp.status(), "token exchange failed");
            return Err(AppError::Auth(format!(
                "token exchange returned {}",
                resp.status()
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Auth(format!("failed to parse token response: {}", e)))?;

        let token = token_resp
            .token
            .or(token_resp.access_token)
            .ok_or_else(|| AppError::Auth("no token in response".into()))?;

        let expires_in = token_resp.expires_in.unwrap_or(300);
        let expires_at = Utc::now() + chrono::Duration::seconds(expires_in.max(30) as i64 - 30);

        // Cache the token
        self.token_cache.insert(
            registry_name.to_string(),
            CachedToken {
                token: token.clone(),
                expires_at,
            },
        );

        tracing::info!(registry = %registry_name, expires_in = %expires_in, "token exchange succeeded, token cached");

        Ok(Some(Self::bearer_header(&token)?))
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

/// Parse a WWW-Authenticate header into key-value pairs.
/// Handles commas inside quoted values (e.g., scope="pull,push").
fn parse_www_authenticate(header: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Strip "Bearer " prefix
    let params_str = header.strip_prefix("Bearer ").unwrap_or(header);

    // Split on commas that are outside of quoted strings
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in params_str.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut current));
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }

    for part in parts {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim().trim_matches('"').to_string();
            map.insert(key, value);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencode_simple() {
        assert_eq!(urlencode("hello"), "hello");
    }

    #[test]
    fn test_urlencode_with_spaces() {
        let encoded = urlencode("hello world");
        assert_eq!(encoded, "hello%20world");
    }

    #[test]
    fn test_urlencode_with_special_chars() {
        let encoded = urlencode("repository:library/nginx:pull,push");
        // Colons, slashes, commas should be encoded
        assert!(encoded.contains("%3A") || encoded.contains("%3a"));
        assert!(encoded.contains("%2F") || encoded.contains("%2f"));
        assert!(encoded.contains("%2C") || encoded.contains("%2c"));
    }

    #[test]
    fn test_urlencode_empty() {
        assert_eq!(urlencode(""), "");
    }

    #[test]
    fn test_parse_www_authenticate_basic() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#;
        let params = parse_www_authenticate(header);
        assert_eq!(params.get("realm").unwrap(), "https://auth.docker.io/token");
        assert_eq!(params.get("service").unwrap(), "registry.docker.io");
        assert_eq!(
            params.get("scope").unwrap(),
            "repository:library/nginx:pull"
        );
    }

    #[test]
    fn test_parse_www_authenticate_with_commas_in_scope() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull,push""#;
        let params = parse_www_authenticate(header);
        assert_eq!(
            params.get("scope").unwrap(),
            "repository:library/nginx:pull,push"
        );
    }

    #[test]
    fn test_parse_www_authenticate_no_bearer_prefix() {
        let header = r#"realm="https://example.com",service="test""#;
        let params = parse_www_authenticate(header);
        assert_eq!(params.get("realm").unwrap(), "https://example.com");
        assert_eq!(params.get("service").unwrap(), "test");
    }

    #[test]
    fn test_parse_www_authenticate_empty() {
        let params = parse_www_authenticate("");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_www_authenticate_bearer_only() {
        let params = parse_www_authenticate("Bearer ");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_www_authenticate_case_insensitive_keys() {
        let header = r#"Bearer Realm="https://auth.example.com",Service="test""#;
        let params = parse_www_authenticate(header);
        // Keys should be lowercased
        assert_eq!(params.get("realm").unwrap(), "https://auth.example.com");
        assert_eq!(params.get("service").unwrap(), "test");
    }

    #[tokio::test]
    async fn test_get_auth_header_none_config() {
        let auth_manager = AuthManager::new();
        let result = auth_manager.get_auth_header("test", None).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_auth_header_basic() {
        let auth_manager = AuthManager::new();
        let config = AuthConfig::Basic {
            username: "user".to_string(),
            password: Some("pass".to_string()),
            password_file: None,
        };
        let result = auth_manager
            .get_auth_header("test", Some(&config))
            .await
            .unwrap();
        assert!(result.is_some());
        let val = result.unwrap();
        let val_str = val.to_str().unwrap();
        assert!(val_str.starts_with("Basic "));
        // Decode and verify
        let encoded_part = val_str.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_part)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "user:pass");
    }

    #[tokio::test]
    async fn test_get_auth_header_basic_no_password() {
        let auth_manager = AuthManager::new();
        let config = AuthConfig::Basic {
            username: "user".to_string(),
            password: None,
            password_file: None,
        };
        let result = auth_manager
            .get_auth_header("test", Some(&config))
            .await
            .unwrap();
        assert!(result.is_some());
        let val = result.unwrap();
        let val_str = val.to_str().unwrap();
        let encoded_part = val_str.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_part)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "user:");
    }

    #[tokio::test]
    async fn test_get_auth_header_bearer() {
        let auth_manager = AuthManager::new();
        let config = AuthConfig::Bearer {
            token: "my-secret-token".to_string(),
        };
        let result = auth_manager
            .get_auth_header("test", Some(&config))
            .await
            .unwrap();
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val.to_str().unwrap(), "Bearer my-secret-token");
    }
}
