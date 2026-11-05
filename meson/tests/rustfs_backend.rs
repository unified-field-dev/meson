//! RustFS FileByteBackend live integration (requires MESON_RUSTFS_* + reachable endpoint).
//!
//! Scenario IDs: `meson-rustfs-put-get-delete-happy`, `meson-rustfs-auth-sad`,
//! `meson-rustfs-not-found-sad`, plus InvalidKey without network.

#![cfg(feature = "backend-rustfs")]

mod support;

use meson::{FileByteBackend, FileStoreError, RustFsBlobStore};

fn require_or_skip(scenario: &str) -> bool {
    support::rustfs_available(scenario)
}

fn store_from_env() -> RustFsBlobStore {
    let endpoint = std::env::var("MESON_RUSTFS_ENDPOINT").expect("endpoint");
    let bucket = std::env::var("MESON_RUSTFS_BUCKET").expect("bucket");
    let access = std::env::var("MESON_RUSTFS_ACCESS_KEY").expect("access");
    let secret = std::env::var("MESON_RUSTFS_SECRET_KEY").expect("secret");
    let region = std::env::var("MESON_RUSTFS_REGION").unwrap_or_else(|_| "us-east-1".into());
    RustFsBlobStore::new(endpoint, bucket, access, secret, region).expect("client")
}

#[tokio::test]
async fn meson_rustfs_put_get_delete_happy() {
    if !require_or_skip("meson-rustfs-put-get-delete-happy") {
        return;
    }
    let store = store_from_env();
    store.ensure_bucket().await.expect("ensure_bucket");
    let key = format!(
        "meson-it-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    store.put(&key, b"hello-rustfs").await.expect("put");
    assert_eq!(store.get(&key).await.expect("get"), b"hello-rustfs");
    store.delete(&key).await.expect("delete");
    assert!(matches!(
        store.get(&key).await.unwrap_err(),
        FileStoreError::NotFound
    ));
}

#[tokio::test]
async fn meson_rustfs_not_found_sad() {
    if !require_or_skip("meson-rustfs-not-found-sad") {
        return;
    }
    let store = store_from_env();
    store.ensure_bucket().await.expect("ensure_bucket");
    let err = store
        .get("definitely-missing-meson-key-zzzz.bin")
        .await
        .unwrap_err();
    assert!(matches!(err, FileStoreError::NotFound));
}

#[tokio::test]
async fn meson_rustfs_auth_sad() {
    if !require_or_skip("meson-rustfs-auth-sad") {
        return;
    }
    let endpoint = std::env::var("MESON_RUSTFS_ENDPOINT").unwrap();
    let bucket = std::env::var("MESON_RUSTFS_BUCKET").unwrap();
    let region = std::env::var("MESON_RUSTFS_REGION").unwrap_or_else(|_| "us-east-1".into());
    let bad = RustFsBlobStore::new(
        endpoint,
        bucket,
        "wrong-access-key",
        "wrong-secret-key-value",
        region,
    )
    .expect("client");
    let err = bad.put("auth-probe.bin", b"x").await.unwrap_err();
    assert!(
        matches!(
            err,
            FileStoreError::Unauthorized | FileStoreError::Io { .. }
        ),
        "bad credentials must not succeed: {err:?}"
    );
}

#[tokio::test]
async fn meson_rustfs_invalid_key_no_network() {
    // Construct without needing a live endpoint (client build only).
    let store = RustFsBlobStore::new("http://127.0.0.1:9", "bucket", "k", "s", "us-east-1")
        .expect("client");
    assert!(matches!(
        store.put("../x", b"x").await.unwrap_err(),
        FileStoreError::InvalidKey
    ));
    assert!(matches!(
        store.put("a/b", b"x").await.unwrap_err(),
        FileStoreError::InvalidKey
    ));
}
