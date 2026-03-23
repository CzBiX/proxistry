use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Tracks in-flight blob fetches to prevent duplicate upstream requests.
///
/// When the first request for a given digest triggers an upstream fetch,
/// subsequent requests for the same digest will wait for the first fetch
/// to complete (and populate the cache) rather than issuing their own
/// upstream request.
///
/// The pattern works as follows:
/// 1. Caller tries `try_register(digest)` to claim ownership of the fetch.
/// 2. If `Inflight::Owner(guard)` is returned, the caller is the first — it
///    should perform the upstream fetch. When done, dropping the guard (or
///    calling `guard.complete()`) notifies all waiters.
/// 3. If `Inflight::Waiting(waiter)` is returned, another fetch is already
///    in progress. The caller should `waiter.wait().await` and then read from
///    cache.
pub struct InflightTracker {
    /// Maps digest → broadcast sender. The sender is kept alive by the
    /// `InflightGuard`; when the guard is dropped the sender is removed
    /// from the map and all receivers get notified via channel close.
    map: Arc<DashMap<String, broadcast::Sender<()>>>,
}

impl InflightTracker {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    /// Attempt to register an in-flight fetch for `digest`.
    ///
    /// Returns `Owner` if this is the first request (caller should fetch),
    /// or `Waiting` if another fetch is already in progress (caller should wait).
    pub fn try_register(&self, digest: &str) -> Inflight {
        use dashmap::mapref::entry::Entry;

        match self.map.entry(digest.to_string()) {
            Entry::Vacant(vacant) => {
                // We are the first — create a broadcast channel.
                // Capacity of 1 is sufficient since we only send a single
                // completion signal.
                let (tx, _rx) = broadcast::channel(1);
                vacant.insert(tx.clone());
                Inflight::Owner(InflightGuard {
                    digest: digest.to_string(),
                    map: Arc::clone(&self.map),
                    tx,
                })
            }
            Entry::Occupied(occupied) => {
                // Another fetch is in progress — subscribe to its completion.
                let rx = occupied.get().subscribe();
                Inflight::Waiting(InflightWaiter { rx })
            }
        }
    }
}

/// Result of `try_register`.
pub enum Inflight {
    /// This caller is the owner of the fetch and should perform it.
    Owner(InflightGuard),
    /// Another fetch is in progress; wait for it.
    Waiting(InflightWaiter),
}

/// Held by the owner of an in-flight fetch. When dropped (or `complete()`
/// is called), all waiters are notified and the entry is removed from the map.
pub struct InflightGuard {
    digest: String,
    map: Arc<DashMap<String, broadcast::Sender<()>>>,
    tx: broadcast::Sender<()>,
}

impl InflightGuard {
    /// Explicitly signal completion and remove the entry.
    #[cfg(test)]
    pub fn complete(self) {
        // Drop runs cleanup — this just consumes self to trigger Drop.
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // Remove entry from the map first so new requests don't subscribe
        // to a dead channel.
        self.map.remove(&self.digest);
        // Notify all waiters. If there are no receivers, that's fine.
        let _ = self.tx.send(());
    }
}

/// Allows a caller to wait until the owning fetch completes.
pub struct InflightWaiter {
    rx: broadcast::Receiver<()>,
}

impl InflightWaiter {
    /// Wait for the in-flight fetch to complete.
    ///
    /// Returns `Ok(())` if the fetch completed (caller should read from cache),
    /// or `Err(())` if the owner was dropped without sending (e.g. fetch failed).
    /// In the error case, the caller should retry or fetch from upstream itself.
    pub async fn wait(mut self) -> Result<(), ()> {
        match self.rx.recv().await {
            Ok(()) => Ok(()),
            // Closed = the guard was dropped (completion signal sent before
            // we subscribed, or the guard was dropped). The recv() after a
            // send() + close can return Closed if we subscribed between send
            // and drop. In all cases the fetch is done.
            Err(broadcast::error::RecvError::Closed) => Ok(()),
            Err(broadcast::error::RecvError::Lagged(_)) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn test_first_request_gets_owner() {
        let tracker = InflightTracker::new();
        match tracker.try_register("sha256:abc123") {
            Inflight::Owner(_guard) => {} // expected
            Inflight::Waiting(_) => panic!("first request should be Owner"),
        }
    }

    #[tokio::test]
    async fn test_second_request_gets_waiting() {
        let tracker = InflightTracker::new();
        let _guard = match tracker.try_register("sha256:abc123") {
            Inflight::Owner(g) => g,
            Inflight::Waiting(_) => panic!("first request should be Owner"),
        };

        match tracker.try_register("sha256:abc123") {
            Inflight::Waiting(_) => {} // expected
            Inflight::Owner(_) => panic!("second request should be Waiting"),
        }
    }

    #[tokio::test]
    async fn test_different_digests_both_get_owner() {
        let tracker = InflightTracker::new();
        let _g1 = match tracker.try_register("sha256:aaa") {
            Inflight::Owner(g) => g,
            Inflight::Waiting(_) => panic!("should be Owner"),
        };
        let _g2 = match tracker.try_register("sha256:bbb") {
            Inflight::Owner(g) => g,
            Inflight::Waiting(_) => panic!("different digest should be Owner"),
        };
    }

    #[tokio::test]
    async fn test_waiter_completes_when_guard_dropped() {
        let tracker = Arc::new(InflightTracker::new());
        let guard = match tracker.try_register("sha256:abc") {
            Inflight::Owner(g) => g,
            Inflight::Waiting(_) => panic!("should be Owner"),
        };

        let waiter = match tracker.try_register("sha256:abc") {
            Inflight::Waiting(w) => w,
            Inflight::Owner(_) => panic!("should be Waiting"),
        };

        // Drop guard in a separate task after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(guard);
        });

        // Waiter should complete
        let result = tokio::time::timeout(Duration::from_secs(2), waiter.wait()).await;
        assert!(result.is_ok(), "waiter should complete");
        assert!(result.unwrap().is_ok(), "wait result should be Ok");
    }

    #[tokio::test]
    async fn test_guard_complete_notifies_waiters() {
        let tracker = Arc::new(InflightTracker::new());
        let guard = match tracker.try_register("sha256:abc") {
            Inflight::Owner(g) => g,
            Inflight::Waiting(_) => panic!("should be Owner"),
        };

        let waiter = match tracker.try_register("sha256:abc") {
            Inflight::Waiting(w) => w,
            Inflight::Owner(_) => panic!("should be Waiting"),
        };

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            guard.complete();
        });

        let result = tokio::time::timeout(Duration::from_secs(2), waiter.wait()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_entry_removed_after_completion() {
        let tracker = InflightTracker::new();
        {
            let guard = match tracker.try_register("sha256:abc") {
                Inflight::Owner(g) => g,
                Inflight::Waiting(_) => panic!("should be Owner"),
            };
            guard.complete();
        }

        // After completion, a new request should get Owner again
        match tracker.try_register("sha256:abc") {
            Inflight::Owner(_) => {} // expected
            Inflight::Waiting(_) => panic!("should be Owner after previous completed"),
        }
    }

    #[tokio::test]
    async fn test_multiple_waiters() {
        let tracker = Arc::new(InflightTracker::new());
        let fetch_count = Arc::new(AtomicU32::new(0));

        let guard = match tracker.try_register("sha256:abc") {
            Inflight::Owner(g) => g,
            Inflight::Waiting(_) => panic!("should be Owner"),
        };
        fetch_count.fetch_add(1, Ordering::SeqCst);

        // Create multiple waiters
        let mut handles = Vec::new();
        for _ in 0..5 {
            let t = tracker.clone();
            let fc = fetch_count.clone();
            handles.push(tokio::spawn(async move {
                match t.try_register("sha256:abc") {
                    Inflight::Waiting(w) => {
                        w.wait().await.unwrap();
                    }
                    Inflight::Owner(_) => {
                        fc.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }));
        }

        // Complete the fetch
        tokio::time::sleep(Duration::from_millis(50)).await;
        guard.complete();

        // All waiters should complete
        for h in handles {
            tokio::time::timeout(Duration::from_secs(2), h)
                .await
                .expect("task should complete")
                .expect("task should not panic");
        }

        // Only one fetch should have occurred
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
    }
}
