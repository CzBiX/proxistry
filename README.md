# Proxistry

A pull-through proxy for Docker/OCI container registries.

Proxistry sits between your container runtime and upstream registries, transparently caching image manifests and blobs to reduce bandwidth, speed up pulls, and bypass network issues.

## Features

- **Push support** -- Allowing you to use it as a transparent cache for both pulls and pushes.
- **Multi-registry proxy** -- A single instance proxies any number of upstream registries (Docker Hub, GHCR, private registries, etc.).
- **Manifest & blob caching** -- Manifests and blobs are cached on disk with independent, configurable TTLs.
- **LRU eviction** -- Automatically evicts least-recently-used entries when cache exceeds the configured size limit.
- **Streaming tee** -- Cache misses are streamed to the client and written to cache simultaneously.
- **Request deduplication** -- Concurrent requests for the same uncached blob are coalesced into a single upstream fetch.
- **Range requests** -- Supports HTTP range requests for efficient blob caching and retrieval.
- **Registry whitelist** -- Optionally restrict which upstream registries are allowed.

## Configuration

Proxistry is configured via a TOML file (default: `config.toml`). All fields are optional with sensible defaults.

See [`config.example.toml`](config.example.toml) for a minimal example.

## Client Setup

Proxistry uses path-based routing. Below are the ways to configure Docker and Podman to use Proxistry.

### Docker

Add Proxistry as a registry mirror in `/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["http://localhost:8000"]
}
```

Restart the Docker daemon. Docker Hub pulls will now go through Proxistry automatically.

For non-Hub registries, reference images with the Proxistry host directly:

```bash
docker pull localhost:8000/ghcr.io/owner/image:tag
```

### Podman

Configure a mirror in `/etc/containers/registries.conf`:

```toml
[[registry]]
location = "docker.io"

[[registry.mirror]]
location = "localhost:8000/docker.io"
insecure = true
```

Then pull as usual:

```bash
podman pull docker.io/library/nginx:latest
```

For other registries, add additional `[[registry]]` blocks or pull via the Proxistry host:

```bash
podman pull localhost:8000/ghcr.io/owner/image:tag
```
