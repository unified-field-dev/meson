//! Shared Valence boot helpers for Meson integration tests.

#![allow(clippy::expect_used)]
#![allow(dead_code)]
#![allow(missing_docs)]

use chrono::Utc;
use meson::generated::{E2eMesonFile, E2eMesonProfilePhoto, FileFileStatus};
use meson::touch_schema_inventory;
use std::sync::Arc;
use valence::{
    register_backend_logical_names, Actor, DatabaseBackend, DatabaseRouter, Model, RecordId,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

pub const OWNER_USER_ID: &str = "meson-owner";
pub const PEER_USER_ID: &str = "meson-peer";
pub const OWNER_FILE_ID: &str = "owner-file-1";
pub const PEER_FILE_ID: &str = "peer-file-1";
pub const OWNER_PHOTO_ID: &str = "owner-photo-1";

/// Serialize tests that mutate the process-wide [`meson::install_blob_store`].
///
/// Also forces `MESON_VIRUS_SCAN=off` so legacy Available-path tests stay stable;
/// virus-scan-specific tests re-enable scan under the same lock.
pub async fn blob_install_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let guard = LOCK.lock().await;
    // SAFETY: test harness only; serialized by LOCK.
    unsafe {
        std::env::set_var("MESON_VIRUS_SCAN", "off");
    }
    guard
}

pub fn owner_rid() -> RecordId {
    RecordId::new("user", OWNER_USER_ID)
}

pub fn peer_rid() -> RecordId {
    RecordId::new("user", PEER_USER_ID)
}

pub async fn setup_valence() -> Valence {
    setup_valence_with_router().await.0
}

/// Like [`setup_valence`], plus the router and default backend key so tests can
/// build Boson execution-context factories over the same database.
pub async fn setup_valence_with_router() -> (Valence, Arc<DatabaseRouter>, String) {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    touch_schema_inventory();

    if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
        // SAFETY: test harness only; OnceLock reads this before first ownership get.
        unsafe {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }

    let backend: Arc<dyn DatabaseBackend> = Arc::new(
        SqliteBackend::connect_memory()
            .await
            .expect("SqliteBackend::connect_memory"),
    );
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        backend,
        &["default"],
        RegisterBackendLogicalNamesOptions::default(),
    );

    let router = Arc::new(router);
    let default_key = valence::router_key("default", SQLITE_ENGINE_ID);
    let valence = Valence::builder()
        .database_router(Arc::clone(&router))
        .default_backend_key(default_key.clone())
        .with_actor(Actor::System {
            operation: "meson_test".to_string(),
        })
        .build()
        .expect("build valence");
    valence
        .sync_typed_tables_from_registry()
        .await
        .expect("sync_typed_tables_from_registry");
    (valence, router, default_key)
}

pub fn as_user(base: &Valence, user_id: &str) -> Valence {
    base.with_actor(Actor::User {
        user_id: user_id.to_string(),
    })
}

pub async fn seed_file(
    valence: &Valence,
    id: &str,
    uploader: RecordId,
    file_name: &str,
    mime: &str,
    storage_path: &str,
    size_bytes: i64,
) {
    let extension = file_name.rsplit('.').next().unwrap_or("bin").to_string();
    let row = E2eMesonFile::new(
        file_name.to_string(),
        extension,
        mime.to_string(),
        size_bytes,
        storage_path.to_string(),
        FileFileStatus::Available,
        uploader,
        Utc::now(),
    )
    .expect("E2eMesonFile::new");
    E2eMesonFile::upsert(id, row, valence, valence::use_!(r"**Test:** Fixture **E2e Meson File** save for `support` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert e2e_meson_file");
}

pub async fn seed_profile_photo(
    valence: &Valence,
    id: &str,
    uploader: RecordId,
    file_name: &str,
    mime: &str,
    storage_path: &str,
    size_bytes: i64,
) {
    let extension = file_name.rsplit('.').next().unwrap_or("bin").to_string();
    let row = E2eMesonProfilePhoto::new(
        Some(64),
        Some(64),
        file_name.to_string(),
        extension,
        mime.to_string(),
        size_bytes,
        storage_path.to_string(),
        FileFileStatus::Available,
        uploader,
        Utc::now(),
    )
    .expect("E2eMesonProfilePhoto::new");
    E2eMesonProfilePhoto::upsert(id, row, valence, valence::use_!(r"**Test:** Fixture **E2e Meson Profile Photo** save for `support` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("upsert e2e_meson_profile_photo");
}
