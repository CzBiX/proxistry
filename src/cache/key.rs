/// Generate cache keys for different content types.
///
/// Cache key layout:
///   Manifests:  manifests/{registry}/{name}/{digest_or_tag}
///   Blobs:      blobs/sha256/{first_2_chars}/{digest}
///   Tag index:  index/{registry}/{name}/{tag}

/// Generate a cache key for a manifest.
pub fn manifest_key(registry: &str, name: &str, reference: &str) -> String {
    format!("manifests/{}/{}/{}", registry, name, reference)
}

/// Generate a cache key for a blob (content-addressed, shared across registries).
pub fn blob_key(digest: &str) -> String {
    // digest format: "sha256:abcdef..."
    let (algo, hash) = digest.split_once(":").unwrap();
    let prefix = if hash.len() >= 2 { &hash[..2] } else { hash };
    format!("blobs/{}/{}/{}", algo, prefix, hash)
}

/// Generate a cache key for a tag→digest index entry.
pub fn tag_index_key(registry: &str, name: &str, tag: &str) -> String {
    format!("index/{}/{}/{}", registry, name, tag)
}

/// Check if a reference looks like a digest (sha256:...).
pub fn is_digest(reference: &str) -> bool {
    reference.starts_with("sha256:") || reference.starts_with("sha512:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_key() {
        assert_eq!(
            manifest_key("docker.io", "library/nginx", "sha256:abc123"),
            "manifests/docker.io/library/nginx/sha256:abc123"
        );
    }

    #[test]
    fn test_blob_key() {
        let key = blob_key("sha256:abcdef1234567890");
        assert_eq!(key, "blobs/sha256/ab/abcdef1234567890");
    }

    #[test]
    fn test_tag_index_key() {
        assert_eq!(
            tag_index_key("docker.io", "library/nginx", "latest"),
            "index/docker.io/library/nginx/latest"
        );
    }

    #[test]
    fn test_is_digest() {
        assert!(is_digest("sha256:abc123"));
        assert!(!is_digest("latest"));
        assert!(!is_digest("v1.0"));
    }
}
