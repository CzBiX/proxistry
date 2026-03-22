use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::cache::key;
use crate::cache::storage::{ByteStream, CacheMetadata, StorageBackend};
use crate::config::AppConfig;
use crate::error::AppResult;

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
    ) -> AppResult<Option<(Bytes, CacheMetadata)>> {
        // If reference is a tag, look up digest from index first
        let cache_key = if key::is_digest(reference) {
            key::manifest_key(registry, name, reference)
        } else {
            // Check tag→digest index
            let index_key = key::tag_index_key(registry, name, reference);
            if let Some((digest_data, index_meta)) = self.storage.get(&index_key).await? {
                let digest = String::from_utf8_lossy(&digest_data).to_string();
                let ttl = self.manifest_ttl(registry);
                // Check if tag index is fresh using metadata from the same read
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
                key::manifest_key(registry, name, &digest)
            } else {
                self.stats.record_miss();
                return Ok(None);
            }
        };

        let ttl = self.manifest_ttl(registry);
        match self.storage.get(&cache_key).await? {
            Some((data, meta)) if is_fresh(&meta, ttl) => {
                tracing::debug!(key = %cache_key, "manifest cache hit");
                self.stats.record_hit();
                Ok(Some((data, meta)))
            }
            Some(_) => {
                tracing::debug!(key = %cache_key, "manifest cache expired");
                self.stats.record_miss();
                // Don't delete yet — let LRU handle stale entries
                Ok(None)
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
    ) -> AppResult<()> {
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
    ) -> AppResult<Option<(ByteStream, CacheMetadata)>> {
        let cache_key = key::blob_key(digest);
        let ttl = self.config.cache.blob_ttl;

        match self.storage.get_stream(&cache_key, range).await? {
            Some((stream, meta)) if is_fresh(&meta, ttl) => {
                tracing::debug!(key = %cache_key, "blob cache hit (stream)");
                self.stats.record_hit();
                Ok(Some((stream, meta)))
            }
            Some(_) => {
                tracing::debug!(key = %cache_key, "blob cache expired");
                self.stats.record_miss();
                Ok(None)
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
    ) -> AppResult<u64> {
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
    ) -> AppResult<()> {
        let cache_key = key::manifest_key(registry, name, reference);
        self.storage.delete(&cache_key).await?;

        if !key::is_digest(reference) {
            let index_key = key::tag_index_key(registry, name, reference);
            self.storage.delete(&index_key).await?;
        }
        Ok(())
    }

    /// Invalidate a blob entry.
    pub async fn invalidate_blob(&self, digest: &str) -> AppResult<()> {
        let cache_key = key::blob_key(digest);
        self.storage.delete(&cache_key).await?;
        Ok(())
    }

    /// Run LRU eviction to bring cache under max size.
    pub async fn run_eviction(&self) -> AppResult<u64> {
        let max_bytes = self.config.cache.max_size_gb * 1024 * 1024 * 1024;
        self.storage.evict_lru(max_bytes).await
    }

    /// Get total cached size.
    pub async fn total_size(&self) -> AppResult<u64> {
        self.storage.total_size().await
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

use chrono::Utc;

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
