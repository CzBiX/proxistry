use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;
use reqwest::Method;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::cache::inflight::Inflight;
use crate::cache::storage::ByteStream;
use crate::error::AppError;
use crate::proxy::rewrite;
use crate::registry::routing::{self, ParsedPath, PathType};
use crate::server::AppState;

const DOCKER_CONTENT_DIGEST: &str = "docker-content-digest";
const DOCKER_UPLOAD_UUID: &str = "docker-upload-uuid";
const X_PROXISTRY_CACHE: &str = "x-proxistry-cache";

/// Parsed byte range from a Range header.
/// Only supports a single "bytes=start-end" range.
#[derive(Debug, Clone, Copy)]
struct ByteRange {
    /// Inclusive start offset
    start: u64,
    /// Inclusive end offset, or None for open-ended (to EOF)
    end: Option<u64>,
}

/// Parse a Range header value like "bytes=0-1023" or "bytes=512-".
/// Returns None if the header is absent, malformed, or uses unsupported multi-ranges.
fn parse_range_header(headers: &HeaderMap) -> Option<ByteRange> {
    let value = headers.get(header::RANGE)?.to_str().ok()?;
    let value = value.strip_prefix("bytes=")?;

    // Only support a single range (no multi-range)
    if value.contains(',') {
        return None;
    }

    let (start_str, end_str) = value.split_once('-')?;

    if start_str.is_empty() {
        // Suffix range like "bytes=-500" — not commonly used in registries, skip
        return None;
    }

    let start: u64 = start_str.parse().ok()?;
    let end: Option<u64> = if end_str.is_empty() {
        None
    } else {
        Some(end_str.parse().ok()?)
    };

    Some(ByteRange { start, end })
}

/// Handle the /v2/ base endpoint (API version check).
pub async fn v2_base() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Docker-Distribution-API-Version", "registry/2.0")],
        "{}",
    )
}

/// Catch-all handler for all /v2/{registry}/... requests.
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response, AppError> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let headers = req.headers().clone();

    // Parse the path
    let parsed = routing::parse_path(&path, method.as_str())?;

    // Check whitelist
    if !routing::is_whitelisted(&state.config, &parsed.registry) {
        return Err(AppError::RegistryBlocked(parsed.registry));
    }

    // Resolve registry config
    let registry = routing::resolve_registry(&state.config, &parsed.registry);

    // Build upstream URL
    let upstream_url = format!(
        "{}{}",
        rewrite::build_upstream_url(&registry, &parsed.upstream_path),
        query
    );

    tracing::info!(
        method = %method,
        registry = %parsed.registry,
        name = %parsed.name,
        upstream_url = %upstream_url,
        "handling request"
    );

    match &parsed.path_type {
        PathType::Manifest { reference } => {
            handle_manifest_get(
                &state,
                &registry,
                &parsed,
                &headers,
                &upstream_url,
                reference,
            )
            .await
        }
        PathType::Blob { digest } => {
            handle_blob_get(&state, &registry, &parsed, &headers, &upstream_url, digest).await
        }
        PathType::TagsList | PathType::Referrers { .. } => {
            // Always proxy tags list and referrers API, never cache
            proxy_passthrough(&state, &registry, Method::GET, &upstream_url, headers, None).await
        }
        PathType::BlobUpload { .. } => {
            // Read body for upload requests
            let body_bytes = axum::body::to_bytes(req.into_body(), 512 * 1024 * 1024)
                .await
                .ok()
                .and_then(|b| if b.is_empty() { None } else { Some(b) });

            let resp = proxy_passthrough(
                &state,
                &registry,
                method,
                &upstream_url,
                headers,
                body_bytes,
            )
            .await?;

            // Rewrite Location header if present
            Ok(rewrite_response_location(
                resp,
                &parsed.registry,
                &registry.url,
                &state.base_url,
            ))
        }
        PathType::ManifestDelete { reference } => {
            let resp = proxy_passthrough(
                &state,
                &registry,
                Method::DELETE,
                &upstream_url,
                headers,
                None,
            )
            .await?;
            // Invalidate cache on successful delete
            if resp.status().is_success() {
                let _ = state
                    .cache
                    .invalidate_manifest(&parsed.registry, &parsed.name, reference)
                    .await;
            }
            Ok(resp)
        }
        PathType::BlobDelete { digest } => {
            let resp = proxy_passthrough(
                &state,
                &registry,
                Method::DELETE,
                &upstream_url,
                headers,
                None,
            )
            .await?;
            if resp.status().is_success() {
                let _ = state.cache.invalidate_blob(digest).await;
            }
            Ok(resp)
        }
        PathType::Other => {
            proxy_passthrough(&state, &registry, method, &upstream_url, headers, None).await
        }
    }
}

/// Handle GET/HEAD for manifests with caching.
async fn handle_manifest_get(
    state: &AppState,
    registry: &crate::config::RegistryConfig,
    parsed: &ParsedPath,
    req_headers: &HeaderMap,
    upstream_url: &str,
    reference: &str,
) -> Result<Response, AppError> {
    // Check cache first
    if let Some((data, meta)) = state
        .cache
        .get_manifest(&parsed.registry, &parsed.name, reference)
        .await?
    {
        tracing::info!(
            registry = %parsed.registry,
            name = %parsed.name,
            reference = %reference,
            "serving manifest from cache"
        );
        return Ok(build_cached_response(data, &meta));
    }

    // Cache miss — fetch from upstream
    let resp = state
        .upstream_client
        .request(
            registry,
            Method::GET,
            upstream_url,
            req_headers.clone(),
            None,
        )
        .await?;

    if !resp.status().is_success() {
        return convert_upstream_response(resp).await;
    }

    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let digest = resp_headers
        .get(DOCKER_CONTENT_DIGEST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp.bytes().await?;

    // Cache the manifest
    if let Err(e) = state
        .cache
        .put_manifest(
            &parsed.registry,
            &parsed.name,
            reference,
            body.clone(),
            content_type.clone(),
            digest.clone(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to cache manifest");
    }

    // Build response
    let mut response =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));

    // Forward relevant headers
    for (key, value) in resp_headers.iter() {
        if key == header::CONTENT_TYPE
            || key.as_str() == DOCKER_CONTENT_DIGEST
            || key == header::ETAG
            || key == header::CONTENT_LENGTH
        {
            response = response.header(key, value);
        }
    }

    Ok(response.body(Body::from(body)).unwrap())
}

/// Handle GET for blobs with streaming cache support and Range request handling.
async fn handle_blob_get(
    state: &AppState,
    registry: &crate::config::RegistryConfig,
    _parsed: &ParsedPath,
    req_headers: &HeaderMap,
    upstream_url: &str,
    digest: &str,
) -> Result<Response, AppError> {
    let range = parse_range_header(req_headers);

    // Check cache first
    let cache_range = range.map(|r| (r.start, r.end));
    if let Some((stream, meta)) = state.cache.get_blob_stream(digest, cache_range).await? {
        if let Some(range) = range {
            let start = range.start;
            let end = range.end.unwrap_or(meta.size - 1).min(meta.size - 1);
            tracing::info!(
                digest = %digest,
                range_start = start,
                range_end = end,
                "serving blob range from cache"
            );
            return Ok(build_range_response(stream, &meta, start, end, "HIT"));
        } else {
            tracing::info!(
                digest = %digest,
                "serving blob from cache (stream)"
            );
            return Ok(build_cached_stream_response(stream, &meta));
        }
    }

    // Range request + cache miss: forward directly to upstream with Range header,
    // no caching. This avoids blocking the client while downloading the full blob.
    if range.is_some() {
        tracing::info!(
            digest = %digest,
            "range request cache miss, proxying directly to upstream"
        );
        return proxy_passthrough(
            state,
            registry,
            Method::GET,
            upstream_url,
            req_headers.clone(),
            None,
        )
        .await;
    }

    // No range, cache miss — use singleflight to avoid duplicate upstream fetches.
    // If another request is already fetching this blob, wait for it to finish
    // and then serve from cache.
    match state.blob_inflight.try_register(digest) {
        Inflight::Waiting(waiter) => {
            tracing::info!(
                digest = %digest,
                "blob fetch already in-flight, waiting for completion"
            );

            // Wait for the in-flight fetch to complete
            let _ = waiter.wait().await;

            // Try reading from cache now that the fetch should be done
            let cache_range = range.map(|r| (r.start, r.end));
            if let Some((stream, meta)) = state.cache.get_blob_stream(digest, cache_range).await? {
                tracing::info!(
                    digest = %digest,
                    "serving blob from cache after singleflight wait"
                );
                return Ok(build_cached_stream_response(stream, &meta));
            }

            // Cache still miss (the other fetch may have failed) — fall through
            // to fetch from upstream ourselves. We re-register as owner since
            // the previous entry was removed.
            tracing::warn!(
                digest = %digest,
                "blob not in cache after singleflight wait, fetching from upstream"
            );
            fetch_blob_upstream(state, registry, req_headers, upstream_url, digest).await
        }
        Inflight::Owner(guard) => {
            fetch_blob_upstream_with_guard(
                state,
                registry,
                req_headers,
                upstream_url,
                digest,
                guard,
            )
            .await
        }
    }
}

/// Fetch a blob from upstream, tee to cache, and return a streaming response.
/// This variant holds an `InflightGuard` to notify waiting requests upon completion.
async fn fetch_blob_upstream_with_guard(
    state: &AppState,
    registry: &crate::config::RegistryConfig,
    req_headers: &HeaderMap,
    upstream_url: &str,
    digest: &str,
    guard: crate::cache::inflight::InflightGuard,
) -> Result<Response, AppError> {
    let resp = state
        .upstream_client
        .request(
            registry,
            Method::GET,
            upstream_url,
            req_headers.clone(),
            None,
        )
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            // Drop guard to notify waiters that the fetch failed
            drop(guard);
            return Err(e);
        }
    };

    if !resp.status().is_success() {
        drop(guard);
        return convert_upstream_response(resp).await;
    }

    let resp_headers = resp.headers().clone();
    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let status = resp.status();

    let upstream_stream = resp.bytes_stream();
    let (client_tx, client_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let (cache_tx, cache_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    // Convert cache receiver into a ByteStream for put_blob_stream
    let cache_stream: ByteStream = Box::pin(tokio_stream::wrappers::ReceiverStream::new(cache_rx));

    // Spawn background task to write cache from stream.
    // The inflight guard is moved here so it is dropped (notifying waiters)
    // only after the cache write completes.
    let cache = state.cache.clone();
    let digest_owned = digest.to_string();
    let ct_clone = content_type.clone();
    tokio::spawn(async move {
        let result = cache
            .put_blob_stream(&digest_owned, cache_stream, ct_clone)
            .await;
        // Drop guard after cache write finishes — this notifies all waiters
        // that the blob is now available in cache.
        drop(guard);
        if let Err(e) = result {
            tracing::warn!(error = %e, "failed to cache blob stream");
        }
    });

    // Spawn tee task: reads from upstream, sends to both client and cache channels
    tokio::spawn(async move {
        let mut upstream = std::pin::pin!(upstream_stream);
        while let Some(result) = upstream.next().await {
            match result {
                Ok(chunk) => {
                    // Send to client channel
                    if client_tx.send(Ok(chunk.clone())).await.is_err() {
                        // Client disconnected, still try to feed cache
                        let _ = cache_tx.send(Ok(chunk)).await;
                        // Drain remaining upstream into cache
                        while let Some(r) = upstream.next().await {
                            match r {
                                Ok(c) => {
                                    if cache_tx.send(Ok(c)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    let _ = cache_tx.send(Err(std::io::Error::other(e))).await;
                                    break;
                                }
                            }
                        }
                        return;
                    }
                    // Send to cache channel
                    if cache_tx.send(Ok(chunk)).await.is_err() {
                        // Cache write failed, but keep streaming to client
                        while let Some(r) = upstream.next().await {
                            match r {
                                Ok(c) => {
                                    if client_tx.send(Ok(c)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    let _ = client_tx.send(Err(std::io::Error::other(e))).await;
                                    break;
                                }
                            }
                        }
                        return;
                    }
                }
                Err(e) => {
                    let _ = client_tx
                        .send(Err(std::io::Error::other(e.to_string())))
                        .await;
                    let _ = cache_tx
                        .send(Err(std::io::Error::other("upstream error")))
                        .await;
                    return;
                }
            }
        }
        // Channels are dropped here, signaling EOF to both receivers
    });

    // Build the streaming response from the client receiver
    let body_stream = tokio_stream::wrappers::ReceiverStream::new(client_rx);
    let body = Body::from_stream(body_stream);

    let mut response =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));

    for (key, value) in resp_headers.iter() {
        if key == header::CONTENT_TYPE
            || key.as_str() == DOCKER_CONTENT_DIGEST
            || key == header::CONTENT_LENGTH
            || key == header::ETAG
        {
            response = response.header(key, value);
        }
    }
    response = response.header(X_PROXISTRY_CACHE, "MISS");
    response = response.header(header::ACCEPT_RANGES, "bytes");

    Ok(response.body(body).unwrap())
}

/// Fetch a blob from upstream without an inflight guard (used as fallback
/// when a singleflight wait completed but the blob was not found in cache).
async fn fetch_blob_upstream(
    state: &AppState,
    registry: &crate::config::RegistryConfig,
    req_headers: &HeaderMap,
    upstream_url: &str,
    digest: &str,
) -> Result<Response, AppError> {
    // Register as owner for this retry attempt
    match state.blob_inflight.try_register(digest) {
        Inflight::Owner(guard) => {
            fetch_blob_upstream_with_guard(
                state,
                registry,
                req_headers,
                upstream_url,
                digest,
                guard,
            )
            .await
        }
        Inflight::Waiting(waiter) => {
            // Another request started fetching while we were about to retry —
            // wait for it instead.
            let _ = waiter.wait().await;
            let cache_range = None;
            if let Some((stream, meta)) = state.cache.get_blob_stream(digest, cache_range).await? {
                return Ok(build_cached_stream_response(stream, &meta));
            }
            // If still not in cache, fall back to direct passthrough
            proxy_passthrough(
                state,
                registry,
                Method::GET,
                upstream_url,
                req_headers.clone(),
                None,
            )
            .await
        }
    }
}

/// Pass a request through to upstream without caching.
async fn proxy_passthrough(
    state: &AppState,
    registry: &crate::config::RegistryConfig,
    method: Method,
    url: &str,
    headers: HeaderMap,
    body: Option<Bytes>,
) -> Result<Response, AppError> {
    let resp = state
        .upstream_client
        .request(registry, method, url, headers, body)
        .await?;

    convert_upstream_response(resp).await
}

/// Convert a reqwest::Response to an axum::Response.
async fn convert_upstream_response(resp: reqwest::Response) -> Result<Response, AppError> {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.bytes().await?;

    let mut response = Response::builder()
        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));

    // Forward all safe headers
    for (key, value) in headers.iter() {
        if key == header::CONTENT_TYPE
            || key.as_str() == DOCKER_CONTENT_DIGEST
            || key.as_str() == DOCKER_UPLOAD_UUID
            || key == header::CONTENT_LENGTH
            || key == header::ETAG
            || key == header::WWW_AUTHENTICATE
            || key == header::CONTENT_RANGE
            || key == header::ACCEPT_RANGES
        {
            response = response.header(key, value);
        }
    }

    Ok(response.body(Body::from(body)).unwrap())
}

/// Build a response from cached data (buffered, for manifests).
fn build_cached_response(data: Bytes, meta: &crate::cache::storage::CacheMetadata) -> Response {
    let mut response = Response::builder().status(StatusCode::OK);

    if let Some(ref ct) = meta.content_type {
        response = response.header(header::CONTENT_TYPE, ct.as_str());
    }
    if let Some(ref digest) = meta.digest {
        response = response.header(DOCKER_CONTENT_DIGEST, digest.as_str());
    }
    response = response.header(header::CONTENT_LENGTH, data.len().to_string());
    response = response.header(X_PROXISTRY_CACHE, "HIT");

    response.body(Body::from(data)).unwrap()
}

/// Build a streaming response from cached blob data.
fn build_cached_stream_response(
    stream: ByteStream,
    meta: &crate::cache::storage::CacheMetadata,
) -> Response {
    let mut response = Response::builder().status(StatusCode::OK);

    if let Some(ref ct) = meta.content_type {
        response = response.header(header::CONTENT_TYPE, ct.as_str());
    }
    if let Some(ref digest) = meta.digest {
        response = response.header(DOCKER_CONTENT_DIGEST, digest.as_str());
    }
    response = response.header(header::CONTENT_LENGTH, meta.size.to_string());
    response = response.header(header::ACCEPT_RANGES, "bytes");
    response = response.header(X_PROXISTRY_CACHE, "HIT");

    response.body(Body::from_stream(stream)).unwrap()
}

/// Build a 206 Partial Content response for a byte range.
fn build_range_response(
    stream: ByteStream,
    meta: &crate::cache::storage::CacheMetadata,
    start: u64,
    end: u64,
    cache_status: &str,
) -> Response {
    let content_length = end - start + 1;
    let content_range = format!("bytes {}-{}/{}", start, end, meta.size);

    let mut response = Response::builder().status(StatusCode::PARTIAL_CONTENT);

    if let Some(ref ct) = meta.content_type {
        response = response.header(header::CONTENT_TYPE, ct.as_str());
    }
    if let Some(ref digest) = meta.digest {
        response = response.header(DOCKER_CONTENT_DIGEST, digest.as_str());
    }
    response = response.header(header::CONTENT_LENGTH, content_length.to_string());
    response = response.header(header::CONTENT_RANGE, content_range);
    response = response.header(header::ACCEPT_RANGES, "bytes");
    response = response.header(X_PROXISTRY_CACHE, cache_status);

    response.body(Body::from_stream(stream)).unwrap()
}

/// Rewrite Location headers in responses to point back to the proxy.
fn rewrite_response_location(
    response: Response,
    registry_name: &str,
    registry_url: &str,
    base_url: &str,
) -> Response {
    let (mut parts, body) = response.into_parts();

    if let Some(location) = parts.headers.get(header::LOCATION)
        && let Ok(loc_str) = location.to_str()
    {
        let rewritten =
            rewrite::rewrite_location_header(loc_str, registry_name, registry_url, base_url);
        if let Ok(val) = HeaderValue::from_str(&rewritten) {
            parts.headers.insert(header::LOCATION, val);
        }
    }

    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::storage::CacheMetadata;
    use axum::http::HeaderMap;
    use chrono::Utc;

    // --- parse_range_header tests ---

    #[test]
    fn test_parse_range_header_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=0-1023".parse().unwrap());
        let range = parse_range_header(&headers).unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.end, Some(1023));
    }

    #[test]
    fn test_parse_range_header_open_ended() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=512-".parse().unwrap());
        let range = parse_range_header(&headers).unwrap();
        assert_eq!(range.start, 512);
        assert!(range.end.is_none());
    }

    #[test]
    fn test_parse_range_header_no_header() {
        let headers = HeaderMap::new();
        assert!(parse_range_header(&headers).is_none());
    }

    #[test]
    fn test_parse_range_header_multi_range_unsupported() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=0-100,200-300".parse().unwrap());
        assert!(parse_range_header(&headers).is_none());
    }

    #[test]
    fn test_parse_range_header_suffix_range_unsupported() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=-500".parse().unwrap());
        assert!(parse_range_header(&headers).is_none());
    }

    #[test]
    fn test_parse_range_header_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "invalid".parse().unwrap());
        assert!(parse_range_header(&headers).is_none());
    }

    #[test]
    fn test_parse_range_header_non_numeric() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=abc-def".parse().unwrap());
        assert!(parse_range_header(&headers).is_none());
    }

    #[test]
    fn test_parse_range_header_zero_start() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=0-0".parse().unwrap());
        let range = parse_range_header(&headers).unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.end, Some(0));
    }

    // --- build_cached_response tests ---

    fn make_meta(content_type: Option<&str>, digest: Option<&str>, size: u64) -> CacheMetadata {
        CacheMetadata {
            size,
            content_type: content_type.map(|s| s.to_string()),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
            digest: digest.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_build_cached_response_status_and_headers() {
        let data = Bytes::from("manifest data");
        let meta = make_meta(
            Some("application/vnd.docker.distribution.manifest.v2+json"),
            Some("sha256:abc123"),
            data.len() as u64,
        );
        let resp = build_cached_response(data.clone(), &meta);

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/vnd.docker.distribution.manifest.v2+json"
        );
        assert_eq!(
            resp.headers().get(DOCKER_CONTENT_DIGEST).unwrap(),
            "sha256:abc123"
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_LENGTH).unwrap(),
            &data.len().to_string()
        );
        assert_eq!(resp.headers().get(X_PROXISTRY_CACHE).unwrap(), "HIT");
    }

    #[test]
    fn test_build_cached_response_no_optional_headers() {
        let data = Bytes::from("data");
        let meta = make_meta(None, None, data.len() as u64);
        let resp = build_cached_response(data, &meta);

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::CONTENT_TYPE).is_none());
        assert!(resp.headers().get(DOCKER_CONTENT_DIGEST).is_none());
        assert_eq!(resp.headers().get(X_PROXISTRY_CACHE).unwrap(), "HIT");
    }

    // --- build_cached_stream_response tests ---

    #[test]
    fn test_build_cached_stream_response_headers() {
        let meta = make_meta(
            Some("application/octet-stream"),
            Some("sha256:def456"),
            1024,
        );
        let stream: ByteStream = Box::pin(futures::stream::once(async { Ok(Bytes::from("data")) }));
        let resp = build_cached_stream_response(stream, &meta);

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            resp.headers().get(DOCKER_CONTENT_DIGEST).unwrap(),
            "sha256:def456"
        );
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "1024");
        assert_eq!(resp.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
        assert_eq!(resp.headers().get(X_PROXISTRY_CACHE).unwrap(), "HIT");
    }

    // --- build_range_response tests ---

    #[test]
    fn test_build_range_response_headers() {
        let meta = make_meta(Some("application/octet-stream"), Some("sha256:abc"), 10000);
        let stream: ByteStream =
            Box::pin(futures::stream::once(async { Ok(Bytes::from("partial")) }));
        let resp = build_range_response(stream, &meta, 100, 199, "HIT");

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "100"); // 199 - 100 + 1
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 100-199/10000"
        );
        assert_eq!(resp.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
        assert_eq!(resp.headers().get(X_PROXISTRY_CACHE).unwrap(), "HIT");
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_build_range_response_miss_cache_status() {
        let meta = make_meta(None, None, 5000);
        let stream: ByteStream = Box::pin(futures::stream::once(async { Ok(Bytes::from("x")) }));
        let resp = build_range_response(stream, &meta, 0, 999, "MISS");

        assert_eq!(resp.headers().get(X_PROXISTRY_CACHE).unwrap(), "MISS");
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "1000");
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 0-999/5000"
        );
    }

    // --- v2_base tests ---

    #[tokio::test]
    async fn test_v2_base() {
        let resp = v2_base().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("Docker-Distribution-API-Version")
                .unwrap(),
            "registry/2.0"
        );
    }

    // --- rewrite_response_location tests ---

    #[test]
    fn test_rewrite_response_location_with_location_header() {
        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(
                header::LOCATION,
                "https://registry-1.docker.io/v2/library/nginx/blobs/uploads/uuid",
            )
            .body(Body::empty())
            .unwrap();

        let rewritten = rewrite_response_location(
            response,
            "docker.io",
            "https://registry-1.docker.io",
            "http://localhost:5000",
        );

        assert_eq!(
            rewritten.headers().get(header::LOCATION).unwrap(),
            "http://localhost:5000/v2/docker.io/library/nginx/blobs/uploads/uuid"
        );
    }

    #[test]
    fn test_rewrite_response_location_no_location_header() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();

        let rewritten = rewrite_response_location(
            response,
            "docker.io",
            "https://registry-1.docker.io",
            "http://localhost:5000",
        );

        assert!(rewritten.headers().get(header::LOCATION).is_none());
    }

    #[test]
    fn test_rewrite_response_location_relative() {
        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(header::LOCATION, "/v2/library/nginx/blobs/uploads/uuid")
            .body(Body::empty())
            .unwrap();

        let rewritten = rewrite_response_location(
            response,
            "docker.io",
            "https://registry-1.docker.io",
            "http://localhost:5000",
        );

        // Relative URLs should not be rewritten
        assert_eq!(
            rewritten.headers().get(header::LOCATION).unwrap(),
            "/v2/library/nginx/blobs/uploads/uuid"
        );
    }
}
