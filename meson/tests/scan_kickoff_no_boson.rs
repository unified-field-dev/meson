//! Without a configured Boson runtime, a pending create still succeeds and the
//! row stays `PendingVirusScan` for the sweeper (or a later manual enqueue).
//!
//! Kept in its own test binary: `boson_runtime::configure` is process-global and
//! cannot be undone once another test sets it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use meson::generated::{E2eMesonFile, FileFileStatus};
use meson::{
    clear_blob_stores_for_test, install_blob_store, install_quarantine_store,
    installed_quarantine_store, FileCreateMeta, FileUpload, LocalDiskBlobStore,
};
use support::{blob_install_lock, owner_rid, setup_valence};
use valence::Model;

#[tokio::test]
async fn create_without_boson_stays_pending_sad() {
    let _lock = blob_install_lock().await;
    // SAFETY: blob_install_lock serializes env mutation.
    unsafe {
        std::env::set_var("MESON_VIRUS_SCAN", "on");
    }
    clear_blob_stores_for_test();
    let root = std::env::temp_dir().join(format!(
        "meson-kickoff-noboson-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    install_blob_store(Arc::new(LocalDiskBlobStore::new(root.join("a")))).unwrap();
    install_quarantine_store(Arc::new(LocalDiskBlobStore::new(root.join("q")))).unwrap();
    assert!(boson_runtime::default().is_none());

    let system = setup_valence().await;
    let created = E2eMesonFile::create_with_bytes(
        &system,
        FileCreateMeta {
            file_name: "n.txt".into(),
            file_extension: "txt".into(),
            mime_type: "text/plain".into(),
            uploaded_by: owner_rid(),
        },
        b"waiting",
    )
    .await
    .expect("create succeeds without Boson");
    assert_eq!(created.file_status(), &FileFileStatus::PendingVirusScan);

    let bare = created.id().unwrap().id().to_string();
    let row = E2eMesonFile::get(&bare, &system, valence::use_!(r"**Test:** Reload an **E2e Meson File** in `scan_kickoff_no_boson` to check it stays pending without a queue. CI and developers running the suite only."))
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(row.file_status(), &FileFileStatus::PendingVirusScan);
    assert_eq!(
        installed_quarantine_store()
            .unwrap()
            .get(created.storage_path())
            .await
            .unwrap(),
        b"waiting"
    );

    // SAFETY: still under blob_install_lock.
    unsafe {
        std::env::set_var("MESON_VIRUS_SCAN", "off");
    }
    clear_blob_stores_for_test();
}
