# Cache Decision Flows

## Manifest Request Flow

```
Client Request
    │
    ▼
Is reference a digest? ──Yes──► Generate cache key directly
    │No                           │
    ▼                             │
Look up tag→digest index          │
    │                             │
    ▼                             │
Index hit & fresh? ──No──► Cache Miss
    │Yes
    ▼
Generate cache key from digest
    │
    ▼
Storage.get(cache_key)
    │
    ▼
Found & fresh (age < TTL)? ──No──► Cache Miss
    │Yes
    ▼
Cache Hit → Return data
```

## Blob Request Flow

```
Client Request (with digest)
    │
    ▼
Check inflight tracker
    │
    ├─► Inflight::Owner ──► Fetch upstream
    │                           │
    │                           ├─► Stream to client
    │                           └─► Stream to cache (tee)
    │                                   │
    │                                   ▼
    │                           Drop guard → notify waiters
    │
    ├─► Inflight::Waiting ──► Wait for completion
    │                               │
    │                               ▼
    │                       Read from cache (stream)
    │
    └─► No inflight ──► Storage.get_stream(cache_key, range)
                              │
                              ▼
                        Found & fresh (age < TTL)?
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                Cache Hit           Cache Miss
           Stream from cache    Register inflight
                                Fetch upstream
                                Stream to client + cache
```

## LRU Eviction Flow

```
Background task (every 5 min)
    │
    ▼
Calculate total cache size
    │
    ▼
size > max_size_gb? ──No──► Skip
    │Yes
    ▼
Collect all entries with metadata
    │
    ▼
Sort by last_accessed (ascending)
    │
    ▼
For each entry (oldest first):
    │
    ├─► remaining ≤ target_size? ──Yes──► Done
    │No
    ▼
Delete entry
    │
    ▼
Update remaining size
    │
    └─► Continue to next entry
```

## Freshness Check

```
is_fresh(meta, ttl):
    │
    ▼
age = now - meta.created_at
    │
    ▼
age < ttl? ──Yes──► Fresh (cache hit)
    │No
    ▼
Stale (cache miss)
```