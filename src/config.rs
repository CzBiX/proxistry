use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::AppError;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub whitelist: WhitelistConfig,
    pub registries: Vec<RegistryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: String,
    pub base_url: Option<String>,
    /// Maximum number of concurrent requests per upstream registry
    pub concurrent: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8000".to_string(),
            base_url: None,
            concurrent: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub data_dir: PathBuf,
    pub max_size_gb: u64,
    #[serde(with = "humantime_serde")]
    pub manifest_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub blob_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        let data_dir = if cfg!(target_os = "linux") {
            PathBuf::from("/var/lib/proxistry/cache")
        } else {
            let tmp_dir = std::env::temp_dir();
            tmp_dir.join("proxistry_cache")
        };

        Self {
            data_dir,
            max_size_gb: 4,
            manifest_ttl: Duration::from_secs(30 * 60), // 30 minutes
            blob_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct WhitelistConfig {
    pub enabled: bool,
    pub registries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryConfig {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default, with = "humantime_serde")]
    pub manifest_ttl: Option<Duration>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub tls: TlsConfig,
}

impl RegistryConfig {
    /// Create a default configuration for an unconfigured registry.
    /// Uses the same URL derivation logic as validation.
    pub fn default_for(name: &str) -> Self {
        let url = if name == "docker.io" {
            "https://registry-1.docker.io".to_string()
        } else {
            format!("https://{}", name)
        };
        Self {
            name: name.to_string(),
            url,
            user_agent: None,
            manifest_ttl: None,
            auth: None,
            tls: TlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Bearer {
        token: String,
    },
    Basic {
        username: String,
        #[serde(default)]
        password: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct TlsConfig {
    pub disable: bool,
    pub insecure: bool,
    pub ca_cert: Option<PathBuf>,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let content = std::fs::read_to_string(path);
        let mut config = match content {
            Ok(content) => toml::from_str(&content)
                .map_err(|e| AppError::Config(format!("failed to parse config: {}", e)))?,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "read config failed, using defaults");
                AppConfig::default()
            }
        };

        config.validate()?;
        Ok(config)
    }

    fn validate(&mut self) -> Result<(), AppError> {
        for reg in &mut self.registries {
            if reg.name.is_empty() {
                return Err(AppError::Config("registry name cannot be empty".into()));
            }
            if reg.url.is_empty() {
                if reg.name == "docker.io" {
                    reg.url = "https://registry-1.docker.io".to_string();
                } else {
                    reg.url = if reg.tls.disable {
                        format!("http://{}", reg.name)
                    } else {
                        format!("https://{}", reg.name)
                    };
                }

                tracing::debug!(
                    registry = %reg.name,
                    "registry URL not set, defaulting to {}",
                    reg.url
                );
            }
        }

        if self.whitelist.enabled {
            // Ensure all configured registries are in the whitelist, append if missing
            for reg in &self.registries {
                if !self.whitelist.registries.contains(&reg.name) {
                    self.whitelist.registries.push(reg.name.clone());
                    tracing::debug!(registry = %reg.name, "added registry to whitelist");
                }
            }
        }

        Ok(())
    }

    /// Get the effective manifest TTL for a registry.
    /// Uses registry-specific TTL if set, otherwise falls back to global.
    pub fn manifest_ttl_for(&self, registry_name: &str) -> Duration {
        self.registries
            .iter()
            .find(|r| r.name == registry_name)
            .and_then(|r| r.manifest_ttl)
            .unwrap_or(self.cache.manifest_ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_config_default_for_docker_io() {
        let reg = RegistryConfig::default_for("docker.io");
        assert_eq!(reg.name, "docker.io");
        assert_eq!(reg.url, "https://registry-1.docker.io");
        assert!(reg.user_agent.is_none());
        assert!(reg.manifest_ttl.is_none());
        assert!(reg.auth.is_none());
    }

    #[test]
    fn test_registry_config_default_for_other_registry() {
        let reg = RegistryConfig::default_for("ghcr.io");
        assert_eq!(reg.name, "ghcr.io");
        assert_eq!(reg.url, "https://ghcr.io");
    }

    #[test]
    fn test_registry_config_default_for_custom_registry() {
        let reg = RegistryConfig::default_for("my.registry.local");
        assert_eq!(reg.name, "my.registry.local");
        assert_eq!(reg.url, "https://my.registry.local");
    }

    #[test]
    fn test_manifest_ttl_for_uses_global_default() {
        let config = AppConfig::default();
        let ttl = config.manifest_ttl_for("unknown-registry");
        assert_eq!(ttl, config.cache.manifest_ttl);
    }

    #[test]
    fn test_manifest_ttl_for_uses_registry_specific() {
        let custom_ttl = Duration::from_secs(600);
        let config = AppConfig {
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://registry-1.docker.io".to_string(),
                user_agent: None,
                manifest_ttl: Some(custom_ttl),
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        assert_eq!(config.manifest_ttl_for("docker.io"), custom_ttl);
        // Unknown registry falls back to global
        assert_eq!(
            config.manifest_ttl_for("ghcr.io"),
            config.cache.manifest_ttl
        );
    }

    #[test]
    fn test_manifest_ttl_for_registry_without_custom_ttl() {
        let config = AppConfig {
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://registry-1.docker.io".to_string(),
                user_agent: None,
                manifest_ttl: None, // no custom TTL
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        // Should fall back to global TTL
        assert_eq!(
            config.manifest_ttl_for("docker.io"),
            config.cache.manifest_ttl
        );
    }

    #[test]
    fn test_validate_fills_in_docker_io_url() {
        let mut config = AppConfig {
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: String::new(), // empty
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(config.registries[0].url, "https://registry-1.docker.io");
    }

    #[test]
    fn test_validate_fills_in_generic_registry_url() {
        let mut config = AppConfig {
            registries: vec![RegistryConfig {
                name: "ghcr.io".to_string(),
                url: String::new(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(config.registries[0].url, "https://ghcr.io");
    }

    #[test]
    fn test_validate_fills_in_http_when_tls_disabled() {
        let mut config = AppConfig {
            registries: vec![RegistryConfig {
                name: "my.local".to_string(),
                url: String::new(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig {
                    disable: true,
                    insecure: false,
                    ca_cert: None,
                },
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(config.registries[0].url, "http://my.local");
    }

    #[test]
    fn test_validate_does_not_overwrite_existing_url() {
        let mut config = AppConfig {
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://custom-mirror.example.com".to_string(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(
            config.registries[0].url,
            "https://custom-mirror.example.com"
        );
    }

    #[test]
    fn test_validate_rejects_empty_registry_name() {
        let mut config = AppConfig {
            registries: vec![RegistryConfig {
                name: String::new(),
                url: "https://example.com".to_string(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_whitelist_adds_configured_registries() {
        let mut config = AppConfig {
            whitelist: WhitelistConfig {
                enabled: true,
                registries: vec!["ghcr.io".to_string()],
            },
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://registry-1.docker.io".to_string(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        assert!(
            config
                .whitelist
                .registries
                .contains(&"docker.io".to_string())
        );
        assert!(config.whitelist.registries.contains(&"ghcr.io".to_string()));
    }

    #[test]
    fn test_validate_whitelist_does_not_duplicate() {
        let mut config = AppConfig {
            whitelist: WhitelistConfig {
                enabled: true,
                registries: vec!["docker.io".to_string()],
            },
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://registry-1.docker.io".to_string(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        let count = config
            .whitelist
            .registries
            .iter()
            .filter(|r| *r == "docker.io")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_validate_whitelist_disabled_does_not_modify() {
        let mut config = AppConfig {
            whitelist: WhitelistConfig {
                enabled: false,
                registries: vec![],
            },
            registries: vec![RegistryConfig {
                name: "docker.io".to_string(),
                url: "https://registry-1.docker.io".to_string(),
                user_agent: None,
                manifest_ttl: None,
                auth: None,
                tls: TlsConfig::default(),
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        assert!(config.whitelist.registries.is_empty());
    }

    #[test]
    fn test_server_config_defaults() {
        let sc = ServerConfig::default();
        assert_eq!(sc.listen, "0.0.0.0:8000");
        assert!(sc.base_url.is_none());
        assert_eq!(sc.concurrent, 10);
    }

    #[test]
    fn test_cache_config_defaults() {
        let cc = CacheConfig::default();
        assert_eq!(cc.max_size_gb, 4);
        assert_eq!(cc.manifest_ttl, Duration::from_secs(30 * 60));
        assert_eq!(cc.blob_ttl, Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn test_tls_config_defaults() {
        let tls = TlsConfig::default();
        assert!(!tls.disable);
        assert!(!tls.insecure);
        assert!(tls.ca_cert.is_none());
    }

    #[test]
    fn test_load_nonexistent_file_returns_defaults() {
        let config = AppConfig::load(Path::new("/nonexistent/path/config.toml")).unwrap();
        assert_eq!(config.server.listen, "0.0.0.0:8000");
        assert!(config.registries.is_empty());
    }
}
