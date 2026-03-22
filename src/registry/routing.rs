use crate::config::{AppConfig, RegistryConfig};
use crate::error::{AppError, AppResult};
use regex::Regex;
use std::sync::OnceLock;

fn re_name_component() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$").unwrap())
}

fn re_digest_algorithm() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_+.\-]+$").unwrap())
}

fn re_digest_hex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Fa-f0-9]+$").unwrap())
}

fn re_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9._\-]*$").unwrap())
}

pub fn validate_name(name: &str) -> AppResult<()> {
    if name.is_empty() {
        return Err(AppError::BadRequest("empty repository name".into()));
    }
    for component in name.split('/') {
        if !re_name_component().is_match(component) {
            return Err(AppError::BadRequest(format!(
                "invalid name component: {:?}",
                component
            )));
        }
    }
    Ok(())
}

pub fn validate_digest(digest: &str) -> AppResult<()> {
    let (algorithm, hex) = digest.split_once(':').ok_or_else(|| {
        AppError::BadRequest(format!("invalid digest (missing ':'): {:?}", digest))
    })?;
    if !re_digest_algorithm().is_match(algorithm) {
        return Err(AppError::BadRequest(format!(
            "invalid digest algorithm: {:?}",
            algorithm
        )));
    }
    if !re_digest_hex().is_match(hex) {
        return Err(AppError::BadRequest(format!(
            "invalid digest hex: {:?}",
            hex
        )));
    }
    Ok(())
}

pub fn validate_reference(reference: &str) -> AppResult<()> {
    if reference.is_empty() {
        return Err(AppError::BadRequest("empty reference".into()));
    }
    if reference.contains(':') {
        validate_digest(reference)
    } else {
        if reference.len() > 128 {
            return Err(AppError::BadRequest(format!(
                "tag too long ({} chars, max 128): {:?}",
                reference.len(),
                reference
            )));
        }
        if !re_tag().is_match(reference) {
            return Err(AppError::BadRequest(format!(
                "invalid tag: {:?}",
                reference
            )));
        }
        Ok(())
    }
}

/// Parsed request path information.
#[derive(Debug, Clone)]
pub struct ParsedPath {
    /// The registry host extracted from the path (e.g., "docker.io")
    pub registry: String,
    /// The remaining path after stripping the registry prefix (e.g., "/v2/library/nginx/manifests/latest")
    pub upstream_path: String,
    /// The repository name (e.g., "library/nginx")
    pub name: String,
    /// The path type
    pub path_type: PathType,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum PathType {
    /// GET/HEAD /v2/{name}/manifests/{reference}
    Manifest { reference: String },
    /// GET /v2/{name}/blobs/{digest}
    Blob { digest: String },
    /// POST/PATCH/PUT /v2/{name}/blobs/uploads/...
    BlobUpload { remainder: String },
    /// GET /v2/{name}/tags/list
    TagsList,
    /// DELETE /v2/{name}/manifests/{reference}
    ManifestDelete { reference: String },
    /// DELETE /v2/{name}/blobs/{digest}
    BlobDelete { digest: String },
    /// Other/unknown
    Other,
}

/// Parse a request path into its components.
/// Expected format: /v2/{registry_host}/{name...}/manifests/{reference}
///                   /v2/{registry_host}/{name...}/blobs/{digest}
///                   /v2/{registry_host}/{name...}/blobs/uploads/...
///                   /v2/{registry_host}/{name...}/tags/list
pub fn parse_path(path: &str, method: &str) -> AppResult<ParsedPath> {
    let path = path.trim_start_matches('/');

    // Must start with "v2/"
    let rest = path
        .strip_prefix("v2/")
        .ok_or_else(|| AppError::Internal("path must start with /v2/".into()))?;

    if rest.is_empty() {
        return Err(AppError::Internal("path too short".into()));
    }

    // First segment is the registry host
    let (registry, remainder) = rest
        .split_once('/')
        .ok_or_else(|| AppError::Internal("path must contain registry and name".into()))?;

    // Parse the remaining segments to find the endpoint type
    // The name can contain slashes (e.g., "library/nginx")
    // We need to find the endpoint marker: manifests/, blobs/, tags/
    let (name, path_type, endpoint_path) = parse_endpoint(remainder, method)?;

    let upstream_path = format!("/v2/{}/{}", name, endpoint_path);

    Ok(ParsedPath {
        registry: registry.to_string(),
        upstream_path,
        name: name.to_string(),
        path_type,
    })
}

fn parse_endpoint(path: &str, method: &str) -> AppResult<(String, PathType, String)> {
    // Look for known endpoint markers in the path
    if let Some(idx) = path.find("/manifests/") {
        let name = &path[..idx];
        let reference = &path[idx + "/manifests/".len()..];
        validate_name(name)?;
        validate_reference(reference)?;
        let is_delete = method.eq_ignore_ascii_case("DELETE");
        let path_type = if is_delete {
            PathType::ManifestDelete {
                reference: reference.to_string(),
            }
        } else {
            PathType::Manifest {
                reference: reference.to_string(),
            }
        };
        return Ok((
            name.to_string(),
            path_type,
            format!("manifests/{}", reference),
        ));
    }

    if let Some(idx) = path.find("/blobs/uploads") {
        let name = &path[..idx];
        let remainder = &path[idx + "/blobs/uploads".len()..];
        validate_name(name)?;
        return Ok((
            name.to_string(),
            PathType::BlobUpload {
                remainder: remainder.to_string(),
            },
            format!("blobs/uploads{}", remainder),
        ));
    }

    if let Some(idx) = path.find("/blobs/") {
        let name = &path[..idx];
        let digest = &path[idx + "/blobs/".len()..];
        validate_name(name)?;
        validate_digest(digest)?;
        let is_delete = method.eq_ignore_ascii_case("DELETE");
        let path_type = if is_delete {
            PathType::BlobDelete {
                digest: digest.to_string(),
            }
        } else {
            PathType::Blob {
                digest: digest.to_string(),
            }
        };
        return Ok((name.to_string(), path_type, format!("blobs/{}", digest)));
    }

    if let Some(idx) = path.find("/tags/list") {
        let name = &path[..idx];
        validate_name(name)?;
        return Ok((
            name.to_string(),
            PathType::TagsList,
            "tags/list".to_string(),
        ));
    }

    // Fallback: treat entire remaining path as the endpoint
    Err(AppError::Internal(format!(
        "unrecognized registry API path: {}",
        path
    )))
}

/// Resolve a registry name to its configuration.
/// If the registry is not explicitly configured, returns a default configuration.
pub fn resolve_registry(config: &AppConfig, registry_name: &str) -> RegistryConfig {
    config
        .registries
        .iter()
        .find(|r| r.name == registry_name)
        .cloned()
        .unwrap_or_else(|| {
            tracing::debug!(
                registry = %registry_name,
                "registry not configured, using defaults"
            );
            RegistryConfig::default_for(registry_name)
        })
}

/// Check if a registry is allowed by the whitelist.
pub fn is_whitelisted(config: &AppConfig, registry_name: &str) -> bool {
    if !config.whitelist.enabled {
        return true;
    }
    config
        .whitelist
        .registries
        .iter()
        .any(|r| r == registry_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest_path() {
        let parsed = parse_path("/v2/docker.io/library/nginx/manifests/latest", "GET").unwrap();
        assert_eq!(parsed.registry, "docker.io");
        assert_eq!(parsed.name, "library/nginx");
        assert_eq!(parsed.upstream_path, "/v2/library/nginx/manifests/latest");
        assert!(
            matches!(parsed.path_type, PathType::Manifest { ref reference } if reference == "latest")
        );
    }

    #[test]
    fn test_parse_blob_path() {
        let parsed = parse_path("/v2/ghcr.io/myorg/myapp/blobs/sha256:abc123", "GET").unwrap();
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.name, "myorg/myapp");
        assert!(
            matches!(parsed.path_type, PathType::Blob { ref digest } if digest == "sha256:abc123")
        );
    }

    #[test]
    fn test_parse_tags_list_path() {
        let parsed = parse_path("/v2/gcr.io/myproject/myimage/tags/list", "GET").unwrap();
        assert_eq!(parsed.registry, "gcr.io");
        assert_eq!(parsed.name, "myproject/myimage");
        assert!(matches!(parsed.path_type, PathType::TagsList));
    }

    #[test]
    fn test_parse_blob_upload_path() {
        let parsed = parse_path(
            "/v2/docker.io/library/nginx/blobs/uploads/some-uuid",
            "POST",
        )
        .unwrap();
        assert_eq!(parsed.registry, "docker.io");
        assert_eq!(parsed.name, "library/nginx");
        assert!(matches!(parsed.path_type, PathType::BlobUpload { .. }));
    }

    #[test]
    fn test_parse_delete_manifest() {
        let parsed =
            parse_path("/v2/docker.io/library/nginx/manifests/sha256:abc", "DELETE").unwrap();
        assert!(matches!(
            parsed.path_type,
            PathType::ManifestDelete { ref reference } if reference == "sha256:abc"
        ));
    }

    #[test]
    fn test_parse_delete_blob() {
        let parsed = parse_path("/v2/docker.io/library/nginx/blobs/sha256:abc", "DELETE").unwrap();
        assert!(matches!(
            parsed.path_type,
            PathType::BlobDelete { ref digest } if digest == "sha256:abc"
        ));
    }

    #[test]
    fn test_parse_path_missing_v2_prefix() {
        let result = parse_path("/api/docker.io/library/nginx/manifests/latest", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_too_short() {
        let result = parse_path("/v2/", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_no_name() {
        let result = parse_path("/v2/docker.io", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_unrecognized_endpoint() {
        let result = parse_path("/v2/docker.io/library/nginx/unknown/endpoint", "GET");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nested_name() {
        let parsed = parse_path("/v2/gcr.io/my-project/sub/image/manifests/v1.0", "GET").unwrap();
        assert_eq!(parsed.registry, "gcr.io");
        assert_eq!(parsed.name, "my-project/sub/image");
        assert!(matches!(
            parsed.path_type,
            PathType::Manifest { ref reference } if reference == "v1.0"
        ));
    }

    #[test]
    fn test_resolve_registry_configured() {
        use crate::config::TlsConfig;
        let config = AppConfig {
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://registry-1.docker.io".to_string(),
                user_agent: Some("custom-ua".to_string()),
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        let reg = resolve_registry(&config, "docker.io");
        assert_eq!(reg.name, "docker.io");
        assert_eq!(reg.url, "https://registry-1.docker.io");
        assert_eq!(reg.user_agent.as_deref(), Some("custom-ua"));
    }

    #[test]
    fn test_resolve_registry_unconfigured() {
        let config = AppConfig::default();
        let reg = resolve_registry(&config, "ghcr.io");
        assert_eq!(reg.name, "ghcr.io");
        assert_eq!(reg.url, "https://ghcr.io");
        assert!(reg.user_agent.is_none());
        assert!(reg.auth.is_none());
    }

    #[test]
    fn test_resolve_registry_unconfigured_docker_io() {
        let config = AppConfig::default();
        let reg = resolve_registry(&config, "docker.io");
        assert_eq!(reg.name, "docker.io");
        assert_eq!(reg.url, "https://registry-1.docker.io");
    }

    #[test]
    fn test_is_whitelisted_disabled() {
        let config = AppConfig {
            whitelist: crate::config::WhitelistConfig {
                enabled: false,
                registries: vec![],
            },
            ..Default::default()
        };
        // All registries are allowed when whitelist is disabled
        assert!(is_whitelisted(&config, "anything.io"));
        assert!(is_whitelisted(&config, "evil.io"));
    }

    #[test]
    fn test_is_whitelisted_enabled_and_listed() {
        let config = AppConfig {
            whitelist: crate::config::WhitelistConfig {
                enabled: true,
                registries: vec!["docker.io".to_string(), "ghcr.io".to_string()],
            },
            ..Default::default()
        };
        assert!(is_whitelisted(&config, "docker.io"));
        assert!(is_whitelisted(&config, "ghcr.io"));
    }

    #[test]
    fn test_is_whitelisted_enabled_and_not_listed() {
        let config = AppConfig {
            whitelist: crate::config::WhitelistConfig {
                enabled: true,
                registries: vec!["docker.io".to_string()],
            },
            ..Default::default()
        };
        assert!(!is_whitelisted(&config, "evil.io"));
        assert!(!is_whitelisted(&config, "ghcr.io"));
    }

    #[test]
    fn test_is_whitelisted_enabled_empty_list() {
        let config = AppConfig {
            whitelist: crate::config::WhitelistConfig {
                enabled: true,
                registries: vec![],
            },
            ..Default::default()
        };
        assert!(!is_whitelisted(&config, "docker.io"));
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("library").is_ok());
        assert!(validate_name("library/nginx").is_ok());
        assert!(validate_name("my-project/sub/image").is_ok());
        assert!(validate_name("a0.b1_c2/d3").is_ok());
        assert!(validate_name("abc123").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(validate_name("").is_err()); // empty
        assert!(validate_name("Library").is_err()); // uppercase
        assert!(validate_name("-nginx").is_err()); // leading separator
        assert!(validate_name("nginx-").is_err()); // trailing separator
        assert!(validate_name("nginx..latest").is_err()); // consecutive separators
        assert!(validate_name("nginx--latest").is_err()); // consecutive separators
        assert!(validate_name("lib/").is_err()); // trailing slash → empty component
        assert!(validate_name("/nginx").is_err()); // leading slash → empty component
    }

    // -----------------------------------------------------------------------
    // validate_digest
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_digest_valid() {
        assert!(validate_digest("sha256:abc123def456").is_ok());
        assert!(validate_digest("sha512:ABCDEF0123456789abcdef").is_ok());
        assert!(validate_digest("blake3:00ff").is_ok());
        // algorithm chars: A-Za-z0-9_+.-
        assert!(validate_digest("sha256+b64:deadbeef").is_ok());
    }

    #[test]
    fn test_validate_digest_invalid() {
        assert!(validate_digest("").is_err()); // empty
        assert!(validate_digest("sha256").is_err()); // missing colon
        assert!(validate_digest(":abc").is_err()); // empty algorithm
        assert!(validate_digest("sha256:").is_err()); // empty hex
        assert!(validate_digest("sha256:xyz").is_err()); // non-hex chars
        assert!(validate_digest("sha 256:abc").is_err()); // space in algorithm
        assert!(validate_digest("sha256:abc!").is_err()); // invalid hex char
    }

    #[test]
    fn test_validate_reference_valid_tag() {
        assert!(validate_reference("latest").is_ok());
        assert!(validate_reference("v1.0").is_ok());
        assert!(validate_reference("_internal").is_ok());
        assert!(validate_reference("1.2.3-alpine").is_ok());
    }

    #[test]
    fn test_validate_reference_valid_digest() {
        assert!(validate_reference("sha256:deadbeefcafe1234").is_ok());
        assert!(validate_reference("sha512:ABCDEF01234567890abcdef").is_ok());
    }

    #[test]
    fn test_validate_reference_invalid() {
        assert!(validate_reference("").is_err()); // empty
        assert!(validate_reference(".latest").is_err()); // tag: bad first char
        assert!(validate_reference("-latest").is_err()); // tag: bad first char
        assert!(validate_reference("sha256:xyz").is_err()); // digest: non-hex
        assert!(validate_reference("sha256:").is_err()); // digest: empty hex
        assert!(validate_reference(&"a".repeat(129)).is_err()); // tag: too long
    }

    #[test]
    fn test_invalid_reference_rejected() {
        // Reference with invalid characters
        assert!(
            parse_path(
                "/v2/docker.io/library/nginx/manifests/../../etc/passwd",
                "GET"
            )
            .is_err()
        );
    }

    #[test]
    fn test_invalid_digest_rejected() {
        // Digest with non-hex characters
        assert!(
            parse_path(
                "/v2/docker.io/library/nginx/blobs/sha256:notahexstring!",
                "GET"
            )
            .is_err()
        );
    }

    #[test]
    fn test_invalid_name_component_rejected() {
        // Name component starts with uppercase
        assert!(parse_path("/v2/docker.io/Library/nginx/manifests/latest", "GET").is_err());
    }
}
