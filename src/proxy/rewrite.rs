use crate::config::RegistryConfig;

/// Build the full upstream URL for a request.
///
/// Takes the registry config and the upstream path (already stripped of registry prefix)
/// and constructs the full URL to proxy to.
pub fn build_upstream_url(registry: &RegistryConfig, upstream_path: &str) -> String {
    let base_url = registry.url.trim_end_matches('/');
    format!("{}{}", base_url, upstream_path)
}

/// Rewrite Location headers in upstream responses.
/// Some registries return absolute URLs in Location headers (e.g., for blob uploads).
/// We need to rewrite these to point back to our proxy.
pub fn rewrite_location_header(
    location: &str,
    registry_name: &str,
    registry_url: &str,
    base_url: &str,
) -> String {
    // If the location is relative, leave it as-is
    if !location.starts_with("http://") && !location.starts_with("https://") {
        return location.to_string();
    }

    // If location points to the upstream registry, rewrite it through the proxy
    let registry_base = registry_url.trim_end_matches('/');
    if location.starts_with(registry_base) {
        let path = &location[registry_base.len()..];
        // Strip /v2/ prefix from path since we'll re-add it with registry prefix
        let stripped = path.strip_prefix("/v2/").unwrap_or(path);
        let base = base_url.trim_end_matches('/');
        return format!("{}/v2/{}/{}", base, registry_name, stripped);
    }

    // Otherwise return as-is (could be a different domain for auth, etc.)
    location.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RegistryConfig, TlsConfig};

    fn make_registry() -> RegistryConfig {
        RegistryConfig {
            name: "docker.io".to_string(),
            url: "https://registry-1.docker.io".to_string(),
            user_agent: None,
            manifest_ttl: None,
            auth: None,
            tls: TlsConfig::default(),
        }
    }

    #[test]
    fn test_build_upstream_url() {
        let reg = make_registry();
        assert_eq!(
            build_upstream_url(&reg, "/v2/library/nginx/manifests/latest"),
            "https://registry-1.docker.io/v2/library/nginx/manifests/latest"
        );
    }

    #[test]
    fn test_rewrite_location_relative() {
        let result = rewrite_location_header(
            "/v2/library/nginx/blobs/uploads/uuid",
            "docker.io",
            "https://registry-1.docker.io",
            "http://localhost:5000",
        );
        assert_eq!(result, "/v2/library/nginx/blobs/uploads/uuid");
    }

    #[test]
    fn test_rewrite_location_absolute() {
        let result = rewrite_location_header(
            "https://registry-1.docker.io/v2/library/nginx/blobs/uploads/uuid",
            "docker.io",
            "https://registry-1.docker.io",
            "http://localhost:5000",
        );
        assert_eq!(
            result,
            "http://localhost:5000/v2/docker.io/library/nginx/blobs/uploads/uuid"
        );
    }
}
