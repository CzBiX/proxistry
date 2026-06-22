use bytes::Bytes;
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::cache::key;
use crate::cache::storage::{ByteStream, CacheMetadata, StorageBackend};
use crate::config::AppConfig;

/// Cache statistics.
#[derive(Debug)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl CacheStats {
    pub fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

/// Orchestrates cache reads/writes with TTL and eviction.
pub struct CacheManager {
    storage: Arc<dyn StorageBackend>,
    config: Arc<AppConfig>,
    pub stats: Arc<CacheStats>,
}

impl CacheManager {
    pub fn new(storage: Arc<dyn StorageBackend>, config: Arc<AppConfig>) -> Self {
        Self {
            storage,
            config,
            stats: Arc::new(CacheStats::new()),
        }
    }

    /// Get a cached manifest, respecting TTL.
    pub async fn get_manifest(
        &self,
        registry: &str,
        name: &str,
        reference: &str,
    ) -> anyhow::Result<Option<(Bytes, CacheMetadata)>> {
        let cache_key = if key::is_digest(reference) {
            key::manifest_key(registry, name, reference)
        } else {
            let index_key = key::tag_index_key(registry, name, reference);
            let index_meta = match self.storage.get_meta(&index_key).await? {
                Some(m) => m,
                None => {
                    self.stats.record_miss();
                    return Ok(None);
                }
            };
            let ttl = self.manifest_ttl(registry);
            if !is_fresh(&index_meta, ttl) {
                tracing::debug!(
                    registry = %registry,
                    name = %name,
                    tag = %reference,
                    "tag index entry expired"
                );
                self.stats.record_miss();
                return Ok(None);
            }
            let digest_data = match self.storage.get_data(&index_key).await? {
                Some(d) => d,
                None => {
                    self.stats.record_miss();
                    return Ok(None);
                }
            };
            let digest = String::from_utf8_lossy(&digest_data).to_string();
            key::manifest_key(registry, name, &digest)
        };

        let ttl = self.manifest_ttl(registry);
        let meta = match self.storage.get_meta(&cache_key).await? {
            Some(m) => m,
            None => {
                self.stats.record_miss();
                return Ok(None);
            }
        };

        if !is_fresh(&meta, ttl) {
            tracing::debug!(key = %cache_key, "manifest cache expired");
            self.stats.record_miss();
            return Ok(None);
        }

        match self.storage.get_data(&cache_key).await? {
            Some(data) => {
                tracing::debug!(key = %cache_key, "manifest cache hit");
                self.stats.record_hit();
                Ok(Some((data, meta)))
            }
            None => {
                self.stats.record_miss();
                Ok(None)
            }
        }
    }

    /// Store a manifest in cache.
    pub async fn put_manifest(
        &self,
        registry: &str,
        name: &str,
        reference: &str,
        data: Bytes,
        content_type: Option<String>,
        digest: Option<String>,
    ) -> anyhow::Result<()> {
        let actual_digest = digest.as_deref().unwrap_or(reference);
        let cache_key = key::manifest_key(registry, name, actual_digest);
        let meta = CacheMetadata::new(data.len() as u64, content_type, digest.clone());
        self.storage.put(&cache_key, data, meta).await?;

        // If reference is a tag, also store tag→digest mapping
        if !key::is_digest(reference)
            && let Some(ref d) = digest
        {
            let index_key = key::tag_index_key(registry, name, reference);
            let index_meta = CacheMetadata::new(d.len() as u64, None, None);
            self.storage
                .put(&index_key, Bytes::from(d.clone()), index_meta)
                .await?;
        }

        tracing::debug!(key = %cache_key, "manifest cached");
        Ok(())
    }

    /// Get a cached blob as a stream, respecting TTL.
    /// If `range` is provided as `(start, optional_end)`, only the specified byte
    /// range is streamed.
    /// Returns the stream and metadata if found and fresh.
    pub async fn get_blob_stream(
        &self,
        digest: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> anyhow::Result<Option<(ByteStream, CacheMetadata)>> {
        let cache_key = key::blob_key(digest);
        let ttl = self.config.cache.blob_ttl;

        let meta = match self.storage.get_meta(&cache_key).await? {
            Some(m) => m,
            None => {
                self.stats.record_miss();
                return Ok(None);
            }
        };

        if !is_fresh(&meta, ttl) {
            tracing::debug!(key = %cache_key, "blob cache expired");
            self.stats.record_miss();
            return Ok(None);
        }

        match self.storage.get_stream(&cache_key, range).await? {
            Some(stream) => {
                tracing::debug!(key = %cache_key, "blob cache hit (stream)");
                self.stats.record_hit();
                Ok(Some((stream, meta)))
            }
            None => {
                self.stats.record_miss();
                Ok(None)
            }
        }
    }

    /// Store a blob in cache from a stream.
    /// Returns the total number of bytes written.
    pub async fn put_blob_stream(
        &self,
        digest: &str,
        stream: ByteStream,
        content_type: Option<String>,
    ) -> anyhow::Result<u64> {
        let cache_key = key::blob_key(digest);
        // Size will be updated by put_stream after writing completes
        let meta = CacheMetadata::new(0, content_type, Some(digest.to_string()));
        let written = self.storage.put_stream(&cache_key, stream, meta).await?;
        tracing::debug!(key = %cache_key, bytes = %written, "blob cached (stream)");
        Ok(written)
    }

    /// Invalidate a manifest entry (e.g., on DELETE).
    pub async fn invalidate_manifest(
        &self,
        registry: &str,
        name: &str,
        reference: &str,
    ) -> anyhow::Result<()> {
        let cache_key = key::manifest_key(registry, name, reference);
        self.storage.delete(&cache_key).await?;

        if !key::is_digest(reference) {
            let index_key = key::tag_index_key(registry, name, reference);
            self.storage.delete(&index_key).await?;
        }
        Ok(())
    }

    /// Invalidate a blob entry.
    pub async fn invalidate_blob(&self, digest: &str) -> anyhow::Result<()> {
        let cache_key = key::blob_key(digest);
        self.storage.delete(&cache_key).await?;
        Ok(())
    }

    /// Run TTL cleanup first, then LRU eviction to bring cache under max size.
    pub async fn run_eviction(&self) -> anyhow::Result<u64> {
        let ttl_freed = self.run_ttl_cleanup().await?;
        let max_bytes = self.config.cache.max_size_gb * 1024 * 1024 * 1024;
        let lru_freed = self.storage.evict_lru(max_bytes).await?;
        Ok(ttl_freed + lru_freed)
    }

    /// Remove entries that have exceeded their TTL.
    async fn run_ttl_cleanup(&self) -> anyhow::Result<u64> {
        let entries = self.storage.list_entries().await?;
        let now = Utc::now();
        let mut freed = 0u64;

        for (key, meta) in &entries {
            let ttl = match ttl_for_key(key, &self.config) {
                Some(t) => t,
                None => continue,
            };
            let age = now
                .signed_duration_since(meta.created_at)
                .to_std()
                .unwrap_or(Duration::MAX);
            if age >= ttl
                && self.storage.delete(key).await?
            {
                freed += meta.size;
                tracing::debug!(key = %key, size = %meta.size, "TTL expired, removed entry");
            }
        }

        if freed > 0 {
            tracing::info!(freed_bytes = %freed, "TTL cleanup complete");
        }
        Ok(freed)
    }

    /// Get total cached size.
    pub async fn total_size(&self) -> anyhow::Result<u64> {
        let entries = self.storage.list_entries().await?;
        Ok(entries.iter().map(|(_, meta)| meta.size).sum())
    }

    fn manifest_ttl(&self, registry: &str) -> Duration {
        self.config.manifest_ttl_for(registry)
    }
}

/// Check if a cached entry is still fresh given a TTL.
fn is_fresh(meta: &CacheMetadata, ttl: Duration) -> bool {
    let age = Utc::now()
        .signed_duration_since(meta.created_at)
        .to_std()
        .unwrap_or(Duration::MAX);
    age < ttl
}

/// Determine the TTL for a cache key based on its type and registry.
fn ttl_for_key(key: &str, config: &AppConfig) -> Option<Duration> {
    if key.starts_with("blobs/") {
        Some(config.cache.blob_ttl)
    } else if let Some(rest) = key.strip_prefix("manifests/") {
        let registry = rest.split('/').next()?;
        Some(config.manifest_ttl_for(registry))
    } else if let Some(rest) = key.strip_prefix("index/") {
        let registry = rest.split('/').next()?;
        Some(config.manifest_ttl_for(registry))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn test_cache_stats_new() {
        let stats = CacheStats::new();
        assert_eq!(stats.hit_count(), 0);
        assert_eq!(stats.miss_count(), 0);
    }

    #[test]
    fn test_cache_stats_record_hit() {
        let stats = CacheStats::new();
        stats.record_hit();
        stats.record_hit();
        stats.record_hit();
        assert_eq!(stats.hit_count(), 3);
        assert_eq!(stats.miss_count(), 0);
    }

    #[test]
    fn test_cache_stats_record_miss() {
        let stats = CacheStats::new();
        stats.record_miss();
        stats.record_miss();
        assert_eq!(stats.miss_count(), 2);
        assert_eq!(stats.hit_count(), 0);
    }

    #[test]
    fn test_cache_stats_mixed() {
        let stats = CacheStats::new();
        stats.record_hit();
        stats.record_miss();
        stats.record_hit();
        stats.record_miss();
        stats.record_hit();
        assert_eq!(stats.hit_count(), 3);
        assert_eq!(stats.miss_count(), 2);
    }

    #[test]
    fn test_is_fresh_within_ttl() {
        let meta = CacheMetadata {
            size: 100,
            content_type: None,
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            digest: None,
        };
        let ttl = Duration::from_secs(300);
        assert!(is_fresh(&meta, ttl));
    }

    #[test]
    fn test_is_fresh_expired() {
        let meta = CacheMetadata {
            size: 100,
            content_type: None,
            created_at: Utc::now() - ChronoDuration::seconds(600),
            last_accessed: Utc::now(),
            digest: None,
        };
        let ttl = Duration::from_secs(300);
        assert!(!is_fresh(&meta, ttl));
    }

    #[test]
    fn test_is_fresh_exactly_at_boundary() {
        // Created exactly TTL seconds ago — should be expired (age >= ttl is not fresh)
        let meta = CacheMetadata {
            size: 100,
            content_type: None,
            created_at: Utc::now() - ChronoDuration::seconds(300),
            last_accessed: Utc::now(),
            digest: None,
        };
        let ttl = Duration::from_secs(300);
        // At or past TTL, should not be fresh
        assert!(!is_fresh(&meta, ttl));
    }

    #[test]
    fn test_is_fresh_zero_ttl() {
        let meta = CacheMetadata {
            size: 100,
            content_type: None,
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            digest: None,
        };
        let ttl = Duration::from_secs(0);
        assert!(!is_fresh(&meta, ttl));
    }

    #[test]
    fn test_is_fresh_future_created_at() {
        // If created_at is in the future (clock skew), signed_duration_since will be
        // negative, to_std() returns Duration::MAX, so it should be stale
        let meta = CacheMetadata {
            size: 100,
            content_type: None,
            created_at: Utc::now() + ChronoDuration::seconds(3600),
            last_accessed: Utc::now(),
            digest: None,
        };
        let ttl = Duration::from_secs(300);
        assert!(!is_fresh(&meta, ttl));
    }
}
