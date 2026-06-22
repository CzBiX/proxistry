use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio_util::io::ReaderStream;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub size: u64,
    pub content_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub digest: Option<String>,
}

impl CacheMetadata {
    pub fn new(size: u64, content_type: Option<String>, digest: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            size,
            content_type,
            created_at: now,
            last_accessed: now,
            digest,
        }
    }
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get_data(&self, key: &str) -> Result<Option<Bytes>>;

    async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<Option<ByteStream>>;

    async fn put(&self, key: &str, data: Bytes, meta: CacheMetadata) -> Result<()>;

    async fn put_stream(&self, key: &str, stream: ByteStream, meta: CacheMetadata) -> Result<u64>;

    async fn get_meta(&self, key: &str) -> Result<Option<CacheMetadata>>;

    async fn update_meta(&self, key: &str, meta: &CacheMetadata) -> Result<()>;

    async fn delete(&self, key: &str) -> Result<bool>;

    async fn list_entries(&self) -> Result<Vec<(String, CacheMetadata)>>;

    async fn evict_lru(&self, target_size: u64) -> Result<u64>;
}

pub struct FsStorage {
    base_dir: PathBuf,
}

impl FsStorage {
    pub async fn new(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)
            .await
            .with_context(|| format!("create cache dir {}", base_dir.display()))?;

        let probe = base_dir.join(".write_probe");
        if let Err(e) = fs::write(&probe, b"").await {
            tracing::warn!(
                error = %e,
                dir = %base_dir.display(),
                "cache dir is not writable, cache will not work"
            );
        } else {
            fs::remove_file(&probe).await.ok();
        }

        Ok(Self { base_dir })
    }

    fn check_path(path: PathBuf) -> Result<PathBuf> {
        if path.components().any(|c| c == Component::ParentDir) {
            bail!("invalid cache key: {:?}", path);
        }
        Ok(path)
    }

    fn data_path(&self, key: &str) -> Result<PathBuf> {
        Self::check_path(self.base_dir.join(key))
    }

    fn meta_path(&self, key: &str) -> Result<PathBuf> {
        let mut p = self.base_dir.join(key);
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".meta");
        p.set_file_name(name);
        Self::check_path(p)
    }

    async fn read_meta(&self, key: &str) -> Result<Option<CacheMetadata>> {
        let meta_path = self.meta_path(key)?;
        if !meta_path.exists() {
            return Ok(None);
        }
        let data = fs::read(&meta_path)
            .await
            .with_context(|| format!("read meta {}", meta_path.display()))?;
        let meta: CacheMetadata = serde_json::from_slice(&data).context("parse meta")?;
        Ok(Some(meta))
    }

    async fn write_meta(&self, key: &str, meta: &CacheMetadata) -> Result<()> {
        let meta_path = self.meta_path(key)?;
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create meta dir {}", parent.display()))?;
        }
        let data = serde_json::to_vec(meta).context("serialize meta")?;
        let mut file = fs::File::create(&meta_path)
            .await
            .with_context(|| format!("create meta {}", meta_path.display()))?;
        file.write_all(&data)
            .await
            .with_context(|| format!("write meta {}", meta_path.display()))?;
        file.flush()
            .await
            .with_context(|| format!("flush meta {}", meta_path.display()))?;
        Ok(())
    }

    async fn collect_entries(&self) -> Result<Vec<(String, CacheMetadata)>> {
        let mut entries = Vec::new();
        self.scan_dir(&self.base_dir, &self.base_dir, &mut entries)
            .await?;
        Ok(entries)
    }

    #[async_recursion::async_recursion]
    async fn scan_dir(
        &self,
        dir: &Path,
        base: &Path,
        entries: &mut Vec<(String, CacheMetadata)>,
    ) -> Result<()> {
        let mut read_dir = match fs::read_dir(dir).await {
            Ok(rd) => rd,
            Err(_) => return Ok(()),
        };

        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                self.scan_dir(&path, base, entries).await?;
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".meta") {
                    continue;
                }
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                if let Ok(Some(meta)) = self.read_meta(&rel).await {
                    entries.push((rel, meta));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for FsStorage {
    async fn get_data(&self, key: &str) -> Result<Option<Bytes>> {
        let data_path = self.data_path(key)?;
        if !data_path.exists() {
            return Ok(None);
        }
        let data = fs::read(&data_path)
            .await
            .with_context(|| format!("read {}", data_path.display()))?;
        Ok(Some(Bytes::from(data)))
    }

    async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<Option<ByteStream>> {
        let data_path = self.data_path(key)?;
        if !data_path.exists() {
            return Ok(None);
        }

        let file_size = fs::metadata(&data_path).await?.len();
        let (start, end) = match range {
            Some((s, e)) => {
                if s >= file_size {
                    bail!("range start {} beyond file size {}", s, file_size);
                }
                (s, e.map(|v| v.min(file_size - 1)).unwrap_or(file_size - 1))
            }
            None => (0, file_size.saturating_sub(1)),
        };

        let mut file = fs::File::open(&data_path)
            .await
            .with_context(|| format!("open {}", data_path.display()))?;

        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .with_context(|| format!("seek {}", data_path.display()))?;
        }

        let range_len = end - start + 1;
        let reader = BufReader::new(file.take(range_len));
        let stream: ByteStream = Box::pin(ReaderStream::new(reader));

        Ok(Some(stream))
    }

    async fn put(&self, key: &str, data: Bytes, meta: CacheMetadata) -> Result<()> {
        let data_path = self.data_path(key)?;
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create dir {}", parent.display()))?;
        }

        let mut file = fs::File::create(&data_path)
            .await
            .with_context(|| format!("create {}", data_path.display()))?;
        file.write_all(&data)
            .await
            .with_context(|| format!("write {}", data_path.display()))?;
        file.flush()
            .await
            .with_context(|| format!("flush {}", data_path.display()))?;

        self.write_meta(key, &meta).await?;
        Ok(())
    }

    async fn put_stream(&self, key: &str, stream: ByteStream, meta: CacheMetadata) -> Result<u64> {
        use futures::StreamExt;

        let data_path = self.data_path(key)?;
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create dir {}", parent.display()))?;
        }

        let mut file = fs::File::create(&data_path)
            .await
            .with_context(|| format!("create {}", data_path.display()))?;
        let mut total_bytes: u64 = 0;

        let mut stream = std::pin::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("stream read error")?;
            total_bytes += chunk.len() as u64;
            file.write_all(&chunk)
                .await
                .with_context(|| format!("write {}", data_path.display()))?;
        }
        file.flush()
            .await
            .with_context(|| format!("flush {}", data_path.display()))?;

        let final_meta = CacheMetadata {
            size: total_bytes,
            ..meta
        };
        self.write_meta(key, &final_meta).await?;
        Ok(total_bytes)
    }

    async fn get_meta(&self, key: &str) -> Result<Option<CacheMetadata>> {
        self.read_meta(key).await
    }

    async fn update_meta(&self, key: &str, meta: &CacheMetadata) -> Result<()> {
        self.write_meta(key, meta).await
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        let data_path = self.data_path(key)?;
        let meta_path = self.meta_path(key)?;
        let existed = data_path.exists();

        if data_path.exists() {
            fs::remove_file(&data_path).await.ok();
        }
        if meta_path.exists() {
            fs::remove_file(&meta_path).await.ok();
        }

        Ok(existed)
    }

    async fn list_entries(&self) -> Result<Vec<(String, CacheMetadata)>> {
        self.collect_entries().await
    }

    async fn evict_lru(&self, target_size: u64) -> Result<u64> {
        let mut entries = self.collect_entries().await?;
        let current_size: u64 = entries.iter().map(|(_, meta)| meta.size).sum();

        if current_size <= target_size {
            return Ok(0);
        }

        entries.sort_by_key(|e| e.1.last_accessed);

        let mut freed = 0u64;
        let mut remaining = current_size;

        for (key, meta) in &entries {
            if remaining <= target_size {
                break;
            }
            if self.delete(key).await? {
                let size = meta.size;
                freed += size;
                remaining -= size;
                tracing::debug!(key = %key, size = %size, "evicted cache entry");
            }
        }

        tracing::info!(freed_bytes = %freed, "LRU eviction complete");
        Ok(freed)
    }
}

struct CachedMeta {
    meta: CacheMetadata,
    dirty: bool,
}

pub struct MetaCachedStorage {
    inner: Arc<dyn StorageBackend>,
    meta_cache: DashMap<String, CachedMeta>,
}

impl MetaCachedStorage {
    pub async fn new(inner: Arc<dyn StorageBackend>) -> Result<Self> {
        let entries = inner.list_entries().await?;
        let entry_count = entries.len();
        let total_size: u64 = entries.iter().map(|(_, meta)| meta.size).sum();

        let meta_cache = DashMap::with_capacity(entry_count);
        for (key, meta) in entries {
            meta_cache.insert(key, CachedMeta { meta, dirty: false });
        }

        tracing::info!(
            entries = entry_count,
            total_bytes = total_size,
            "cache storage initialized"
        );

        Ok(Self { inner, meta_cache })
    }

    async fn flush_dirty(&self) {
        for mut entry in self.meta_cache.iter_mut() {
            if entry.value().dirty {
                let _ = self
                    .inner
                    .update_meta(entry.key(), &entry.value().meta)
                    .await;
                entry.value_mut().dirty = false;
            }
        }
    }
}

#[async_trait]
impl StorageBackend for MetaCachedStorage {
    async fn get_data(&self, key: &str) -> Result<Option<Bytes>> {
        let data = self.inner.get_data(key).await?;
        if data.is_some() {
            if let Some(mut entry) = self.meta_cache.get_mut(key) {
                entry.value_mut().meta.last_accessed = Utc::now();
                entry.value_mut().dirty = true;
            } else if let Some(meta) = self.inner.get_meta(key).await? {
                self.meta_cache
                    .insert(key.to_string(), CachedMeta { meta, dirty: false });
            }
        }
        Ok(data)
    }

    async fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<Option<ByteStream>> {
        let validated_range = if let Some((start, end)) = range {
            if let Some(entry) = self.meta_cache.get(key) {
                let file_size = entry.value().meta.size;
                if start >= file_size {
                    bail!("range start {} beyond file size {}", start, file_size);
                }
                let clamped_end = end.map(|v| v.min(file_size - 1)).unwrap_or(file_size - 1);
                Some((start, Some(clamped_end)))
            } else {
                range
            }
        } else {
            None
        };

        let stream = self.inner.get_stream(key, validated_range).await?;
        if stream.is_some() {
            if let Some(mut entry) = self.meta_cache.get_mut(key) {
                entry.value_mut().meta.last_accessed = Utc::now();
                entry.value_mut().dirty = true;
            } else if let Some(meta) = self.inner.get_meta(key).await? {
                self.meta_cache
                    .insert(key.to_string(), CachedMeta { meta, dirty: false });
            }
        }
        Ok(stream)
    }

    async fn put(&self, key: &str, data: Bytes, meta: CacheMetadata) -> Result<()> {
        self.inner.put(key, data, meta.clone()).await?;
        self.meta_cache
            .insert(key.to_string(), CachedMeta { meta, dirty: false });
        Ok(())
    }

    async fn put_stream(&self, key: &str, stream: ByteStream, meta: CacheMetadata) -> Result<u64> {
        let written = self.inner.put_stream(key, stream, meta.clone()).await?;
        let final_meta = CacheMetadata {
            size: written,
            ..meta
        };
        self.meta_cache.insert(
            key.to_string(),
            CachedMeta {
                meta: final_meta,
                dirty: false,
            },
        );
        Ok(written)
    }

    async fn get_meta(&self, key: &str) -> Result<Option<CacheMetadata>> {
        if let Some(entry) = self.meta_cache.get(key) {
            return Ok(Some(entry.value().meta.clone()));
        }
        let meta = self.inner.get_meta(key).await?;
        if let Some(ref m) = meta {
            self.meta_cache.insert(
                key.to_string(),
                CachedMeta {
                    meta: m.clone(),
                    dirty: false,
                },
            );
        }
        Ok(meta)
    }

    async fn update_meta(&self, key: &str, meta: &CacheMetadata) -> Result<()> {
        self.inner.update_meta(key, meta).await?;
        self.meta_cache.insert(
            key.to_string(),
            CachedMeta {
                meta: meta.clone(),
                dirty: false,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        let existed = self.inner.delete(key).await?;
        self.meta_cache.remove(key);
        Ok(existed)
    }

    async fn list_entries(&self) -> Result<Vec<(String, CacheMetadata)>> {
        Ok(self
            .meta_cache
            .iter()
            .map(|e| (e.key().clone(), e.value().meta.clone()))
            .collect())
    }

    async fn evict_lru(&self, target_size: u64) -> Result<u64> {
        let mut entries: Vec<(String, CacheMetadata)> = self
            .meta_cache
            .iter()
            .map(|e| (e.key().clone(), e.value().meta.clone()))
            .collect();

        let current_size: u64 = entries.iter().map(|(_, meta)| meta.size).sum();
        if current_size <= target_size {
            self.flush_dirty().await;
            return Ok(0);
        }

        entries.sort_by_key(|e| e.1.last_accessed);

        let mut freed = 0u64;
        let mut remaining = current_size;

        for (key, meta) in &entries {
            if remaining <= target_size {
                break;
            }
            if self.inner.delete(key).await? {
                self.meta_cache.remove(key);
                let size = meta.size;
                freed += size;
                remaining -= size;
                tracing::debug!(key = %key, size = %size, "evicted cache entry");
            }
        }

        self.flush_dirty().await;
        tracing::info!(freed_bytes = %freed, "LRU eviction complete");
        Ok(freed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_cache_metadata_new() {
        let meta = CacheMetadata::new(
            1024,
            Some("application/json".to_string()),
            Some("sha256:abc".to_string()),
        );
        assert_eq!(meta.size, 1024);
        assert_eq!(meta.content_type.as_deref(), Some("application/json"));
        assert_eq!(meta.digest.as_deref(), Some("sha256:abc"));
        let now = Utc::now();
        assert!((now - meta.created_at).num_seconds().abs() < 2);
        assert!((now - meta.last_accessed).num_seconds().abs() < 2);
    }

    #[test]
    fn test_cache_metadata_new_with_none() {
        let meta = CacheMetadata::new(0, None, None);
        assert_eq!(meta.size, 0);
        assert!(meta.content_type.is_none());
        assert!(meta.digest.is_none());
    }

    #[test]
    fn test_check_path_valid() {
        let path = PathBuf::from("/foo/blobs/sha256/ab/abcdef");
        assert!(FsStorage::check_path(path).is_ok());
    }

    #[test]
    fn test_check_path_rejects_dot_segments() {
        let path = PathBuf::from("/foo/../../bar");
        assert!(FsStorage::check_path(path).is_err());
    }

    #[tokio::test]
    async fn test_fs_storage_new_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("cache_test");
        assert!(!dir.exists());
        let _storage = FsStorage::new(dir.clone()).await.unwrap();
        assert!(dir.exists());
    }

    async fn make_test_storage(tmp: &TempDir) -> FsStorage {
        let cache_dir = tmp.path().join("cache");
        fs::create_dir_all(&cache_dir).await.unwrap();
        FsStorage {
            base_dir: cache_dir,
        }
    }

    #[tokio::test]
    async fn test_data_path() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let expected = storage.base_dir.join("blobs/sha256/ab/abcdef");
        assert!(expected.ends_with("blobs/sha256/ab/abcdef"));
    }

    #[tokio::test]
    async fn test_meta_path_construction() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let mut p = storage.base_dir.join("blobs/sha256/ab/abcdef");
        let mut name = p.file_name().unwrap().to_os_string();
        name.push(".meta");
        p.set_file_name(name);
        assert!(p.ends_with("blobs/sha256/ab/abcdef.meta"));
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let key = "test/item";
        let data = Bytes::from("hello world");
        let meta = CacheMetadata::new(data.len() as u64, Some("text/plain".to_string()), None);

        let data_path = storage.base_dir.join(key);
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        let mut file = fs::File::create(&data_path).await.unwrap();
        file.write_all(&data).await.unwrap();
        file.flush().await.unwrap();
        storage.write_meta(key, &meta).await.ok();

        let read_data = fs::read(&data_path).await.unwrap();
        assert_eq!(read_data, &data[..]);
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let data_path = storage.base_dir.join("nonexistent/key");
        assert!(!data_path.exists());
    }

    #[tokio::test]
    async fn test_delete_file() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let key = "test/delete_me";

        let data_path = storage.base_dir.join(key);
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        fs::write(&data_path, b"delete this").await.unwrap();

        assert!(data_path.exists());
        fs::remove_file(&data_path).await.unwrap();
        assert!(!data_path.exists());
    }

    #[tokio::test]
    async fn test_total_size_empty() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let entries = storage.collect_entries().await.unwrap();
        let total: u64 = entries.iter().map(|(_, meta)| meta.size).sum();
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_put_and_get_stream() {
        let tmp = TempDir::new().unwrap();
        let storage = make_test_storage(&tmp).await;
        let key = "stream/test";
        let data = Bytes::from("streaming data content");

        let data_path = storage.base_dir.join(key);
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        fs::write(&data_path, &data).await.unwrap();

        let meta = CacheMetadata::new(
            data.len() as u64,
            Some("application/octet-stream".to_string()),
            None,
        );
        storage.write_meta(key, &meta).await.ok();

        let read_data = fs::read(&data_path).await.unwrap();
        assert_eq!(read_data, &data[..]);
    }

    #[tokio::test]
    async fn test_cache_metadata_serialization() {
        let meta = CacheMetadata::new(
            1024,
            Some("application/json".to_string()),
            Some("sha256:abc".to_string()),
        );
        let serialized = serde_json::to_vec(&meta).unwrap();
        let deserialized: CacheMetadata = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.size, 1024);
        assert_eq!(
            deserialized.content_type.as_deref(),
            Some("application/json")
        );
        assert_eq!(deserialized.digest.as_deref(), Some("sha256:abc"));
        assert_eq!(deserialized.created_at, meta.created_at);
        assert_eq!(deserialized.last_accessed, meta.last_accessed);
    }

    async fn make_meta_cached_storage(
        tmp: &TempDir,
    ) -> (MetaCachedStorage, Arc<dyn StorageBackend>) {
        let fs_storage = Arc::new(FsStorage {
            base_dir: tmp.path().join("cache"),
        });
        fs::create_dir_all(&fs_storage.base_dir).await.unwrap();
        let inner: Arc<dyn StorageBackend> = fs_storage;
        let wrapper = MetaCachedStorage::new(inner.clone()).await.unwrap();
        (wrapper, inner)
    }

    #[tokio::test]
    async fn test_meta_cached_new_empty() {
        let tmp = TempDir::new().unwrap();
        let (wrapper, _) = make_meta_cached_storage(&tmp).await;
        assert!(wrapper.meta_cache.is_empty());
    }

    #[tokio::test]
    async fn test_meta_cached_preload_on_construction() {
        let tmp = TempDir::new().unwrap();
        let fs_storage = Arc::new(FsStorage {
            base_dir: tmp.path().join("cache"),
        });
        fs::create_dir_all(&fs_storage.base_dir).await.unwrap();

        let key = "preload/test";
        let data = Bytes::from("preload data");
        let meta = CacheMetadata::new(data.len() as u64, None, None);
        fs_storage.put(key, data, meta).await.unwrap();

        let inner: Arc<dyn StorageBackend> = fs_storage;
        let wrapper = MetaCachedStorage::new(inner).await.unwrap();

        assert_eq!(wrapper.meta_cache.len(), 1);
        assert!(wrapper.meta_cache.contains_key(key));
        assert!(!wrapper.meta_cache.get(key).unwrap().value().dirty);
    }

    #[tokio::test]
    async fn test_meta_cached_get_meta_hit() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let key = "meta/hit";
        let meta = CacheMetadata::new(100, Some("text/plain".to_string()), None);
        inner
            .put(key, Bytes::from("data"), meta.clone())
            .await
            .unwrap();

        let wrapper2 = MetaCachedStorage::new(inner).await.unwrap();
        let result = wrapper2.get_meta(key).await.unwrap().unwrap();
        assert_eq!(result.size, 100);
        assert_eq!(result.content_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn test_meta_cached_get_meta_miss() {
        let tmp = TempDir::new().unwrap();
        let (wrapper, _) = make_meta_cached_storage(&tmp).await;
        let result = wrapper.get_meta("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_meta_cached_get_data_updates_last_accessed() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let key = "access/test";
        let meta = CacheMetadata::new(5, None, None);
        inner.put(key, Bytes::from("hello"), meta).await.unwrap();

        let wrapper2 = MetaCachedStorage::new(inner).await.unwrap();
        let original_accessed = wrapper2
            .meta_cache
            .get(key)
            .unwrap()
            .value()
            .meta
            .last_accessed;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let data = wrapper2.get_data(key).await.unwrap().unwrap();
        assert_eq!(&data[..], b"hello");

        let entry = wrapper2.meta_cache.get(key).unwrap();
        assert!(entry.value().meta.last_accessed > original_accessed);
        assert!(entry.value().dirty);
    }

    #[tokio::test]
    async fn test_meta_cached_get_data_miss_populates_cache() {
        let tmp = TempDir::new().unwrap();
        let (wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let key = "miss/populate";
        let meta = CacheMetadata::new(4, None, None);
        inner.put(key, Bytes::from("data"), meta).await.unwrap();

        assert!(!wrapper.meta_cache.contains_key(key));

        let data = wrapper.get_data(key).await.unwrap().unwrap();
        assert_eq!(&data[..], b"data");
        assert!(wrapper.meta_cache.contains_key(key));
    }

    #[tokio::test]
    async fn test_meta_cached_put_inserts_cache() {
        let tmp = TempDir::new().unwrap();
        let (wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let key = "put/test";
        let meta = CacheMetadata::new(5, None, None);
        wrapper.put(key, Bytes::from("world"), meta).await.unwrap();

        assert!(wrapper.meta_cache.contains_key(key));
        assert!(!wrapper.meta_cache.get(key).unwrap().value().dirty);

        let data = inner.get_data(key).await.unwrap().unwrap();
        assert_eq!(&data[..], b"world");
    }

    #[tokio::test]
    async fn test_meta_cached_delete_removes_cache() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let key = "delete/test";
        let meta = CacheMetadata::new(4, None, None);
        inner.put(key, Bytes::from("data"), meta).await.unwrap();

        let wrapper2 = MetaCachedStorage::new(inner).await.unwrap();
        assert!(wrapper2.meta_cache.contains_key(key));

        wrapper2.delete(key).await.unwrap();
        assert!(!wrapper2.meta_cache.contains_key(key));
    }

    #[tokio::test]
    async fn test_meta_cached_list_entries() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        inner
            .put("a", Bytes::from("1"), CacheMetadata::new(1, None, None))
            .await
            .unwrap();
        inner
            .put("b", Bytes::from("22"), CacheMetadata::new(2, None, None))
            .await
            .unwrap();

        let wrapper2 = MetaCachedStorage::new(inner).await.unwrap();
        let entries = wrapper2.list_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        let total: u64 = entries.iter().map(|(_, m)| m.size).sum();
        assert_eq!(total, 3);
    }

    #[tokio::test]
    async fn test_meta_cached_evict_lru() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let mut meta1 = CacheMetadata::new(100, None, None);
        meta1.last_accessed = Utc::now() - chrono::Duration::seconds(10);
        inner
            .put("old", Bytes::from(vec![0u8; 100]), meta1)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let mut meta2 = CacheMetadata::new(100, None, None);
        meta2.last_accessed = Utc::now();
        inner
            .put("new", Bytes::from(vec![0u8; 100]), meta2)
            .await
            .unwrap();

        let wrapper2 = MetaCachedStorage::new(inner.clone()).await.unwrap();
        assert_eq!(wrapper2.meta_cache.len(), 2);

        let freed = wrapper2.evict_lru(150).await.unwrap();
        assert_eq!(freed, 100);
        assert_eq!(wrapper2.meta_cache.len(), 1);
        assert!(wrapper2.meta_cache.contains_key("new"));
        assert!(!wrapper2.meta_cache.contains_key("old"));
    }

    #[tokio::test]
    async fn test_meta_cached_flush_dirty_on_evict() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let meta = CacheMetadata::new(5, None, None);
        inner
            .put("flush/test", Bytes::from("hello"), meta)
            .await
            .unwrap();

        let wrapper2 = MetaCachedStorage::new(inner.clone()).await.unwrap();
        let _ = wrapper2.get_data("flush/test").await.unwrap();

        assert!(wrapper2.meta_cache.get("flush/test").unwrap().value().dirty);

        wrapper2.evict_lru(1000).await.unwrap();

        assert!(!wrapper2.meta_cache.get("flush/test").unwrap().value().dirty);

        let disk_meta = inner.get_meta("flush/test").await.unwrap().unwrap();
        let cached_meta = wrapper2
            .meta_cache
            .get("flush/test")
            .unwrap()
            .value()
            .meta
            .clone();
        assert_eq!(disk_meta.last_accessed, cached_meta.last_accessed);
    }

    #[tokio::test]
    async fn test_meta_cached_update_meta() {
        let tmp = TempDir::new().unwrap();
        let (_wrapper, inner) = make_meta_cached_storage(&tmp).await;

        let key = "update/meta";
        let meta = CacheMetadata::new(10, None, None);
        inner
            .put(key, Bytes::from("0123456789"), meta)
            .await
            .unwrap();

        let wrapper2 = MetaCachedStorage::new(inner.clone()).await.unwrap();

        let new_meta = CacheMetadata::new(10, Some("text/html".to_string()), None);
        wrapper2.update_meta(key, &new_meta).await.unwrap();

        let cached = wrapper2.meta_cache.get(key).unwrap().value().meta.clone();
        assert_eq!(cached.content_type.as_deref(), Some("text/html"));
        assert!(!wrapper2.meta_cache.get(key).unwrap().value().dirty);

        let disk_meta = inner.get_meta(key).await.unwrap().unwrap();
        assert_eq!(disk_meta.content_type.as_deref(), Some("text/html"));
    }
}
