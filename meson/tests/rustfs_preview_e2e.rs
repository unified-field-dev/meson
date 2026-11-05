//! IsolatedLab: FileQueryAll preview against RustFS blob store.
//!
//! Scenario IDs: `meson-preview-image-happy` (rustfs), `meson-preview-forbidden-sad` (rustfs).

#![cfg(feature = "backend-rustfs")]

mod support;

use meson::generated::{FileFields, FileQueryAll};
use meson::{find_file_in_owned_rows, preview_kind, FileByteBackend, PreviewKind, RustFsBlobStore};
use support::{
    as_user, owner_rid, peer_rid, seed_file, setup_valence, OWNER_FILE_ID, OWNER_USER_ID,
    PEER_USER_ID,
};
use valence::{RecordId, RecordPredicate};

fn require_or_skip(id: &str) -> bool {
    support::rustfs_available(id)
}

fn store() -> RustFsBlobStore {
    RustFsBlobStore::new(
        std::env::var("MESON_RUSTFS_ENDPOINT").unwrap(),
        std::env::var("MESON_RUSTFS_BUCKET").unwrap(),
        std::env::var("MESON_RUSTFS_ACCESS_KEY").unwrap(),
        std::env::var("MESON_RUSTFS_SECRET_KEY").unwrap(),
        std::env::var("MESON_RUSTFS_REGION").unwrap_or_else(|_| "us-east-1".into()),
    )
    .expect("store")
}

#[tokio::test]
async fn meson_preview_image_happy_rustfs() {
    if !require_or_skip("meson-preview-image-happy (rustfs)") {
        return;
    }
    let system = setup_valence().await;
    let key = format!(
        "preview-{}.png",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    seed_file(
        &system,
        OWNER_FILE_ID,
        owner_rid(),
        "shot.png",
        "image/png",
        &key,
        5,
    )
    .await;

    let store = store();
    store.ensure_bucket().await.expect("bucket");
    store.put(&key, b"PNG..").await.expect("put");

    let owner_v = as_user(&system, OWNER_USER_ID);
    let rows = FileQueryAll::query(&owner_v, valence::use_!(r"**Test:** Fixture **File Query All** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .where_uploaded_by(RecordPredicate::Equals(owner_rid()))
        .await
        .expect("list");
    let want = RecordId::new("e2e_meson_file", OWNER_FILE_ID);
    let row = find_file_in_owned_rows(rows, &want).expect("owned");
    assert_eq!(preview_kind(row.mime_type()), PreviewKind::Image);
    assert_eq!(store.get(row.storage_path()).await.expect("get"), b"PNG..");
    let _ = store.delete(&key).await;
}

#[tokio::test]
async fn meson_preview_forbidden_sad_rustfs() {
    if !require_or_skip("meson-preview-forbidden-sad (rustfs)") {
        return;
    }
    let system = setup_valence().await;
    seed_file(
        &system,
        OWNER_FILE_ID,
        owner_rid(),
        "secret.png",
        "image/png",
        "secret-rustfs.png",
        5,
    )
    .await;
    let peer_v = as_user(&system, PEER_USER_ID);
    let peer_rows = FileQueryAll::query(&peer_v, valence::use_!(r"**Test:** Fixture **File Query All** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .where_uploaded_by(RecordPredicate::Equals(peer_rid()))
        .await
        .expect("peer list");
    let want = RecordId::new("e2e_meson_file", OWNER_FILE_ID);
    assert!(find_file_in_owned_rows(peer_rows, &want).is_none());
}
