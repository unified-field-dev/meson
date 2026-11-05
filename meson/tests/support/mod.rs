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

/// Decide whether a RustFS test should run, skip, or fail.
///
/// Returns `true` when the `MESON_RUSTFS_*` settings are present and the endpoint
/// accepts a TCP connection (retried for about 10 s so a service container that is
/// still starting is not mistaken for a missing one). Panics if the settings are
/// missing and `MESON_RUSTFS_REQUIRED=1`; logs a skip and returns `false` if they are
/// missing otherwise. If the endpoint is unreachable, skips (returns `false`) when
/// `MESON_RUSTFS_ALLOW_UNREACHABLE=1`; otherwise returns `true` so the real
/// connection error surfaces in the test.
pub fn rustfs_available(scenario: &str) -> bool {
    let var = |k: &str| std::env::var(k).ok();
    let required = var("MESON_RUSTFS_REQUIRED").as_deref() == Some("1");
    let configured = ["ENDPOINT", "BUCKET", "ACCESS_KEY", "SECRET_KEY"]
        .iter()
        .all(|k| var(&format!("MESON_RUSTFS_{k}")).is_some());
    if !configured {
        assert!(
            !required,
            "{scenario}: MESON_RUSTFS_* required (MESON_RUSTFS_REQUIRED=1)"
        );
        eprintln!("skip {scenario}: MESON_RUSTFS_* unset");
        return false;
    }
    let endpoint = var("MESON_RUSTFS_ENDPOINT").expect("configured");
    let addr = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();
    let addr = if addr.contains(':') {
        addr
    } else if endpoint.starts_with("https://") {
        format!("{addr}:443")
    } else {
        format!("{addr}:80")
    };
    for _ in 0..20 {
        let reachable = std::net::ToSocketAddrs::to_socket_addrs(&addr)
            .map(|mut it| {
                it.any(|a| {
                    std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(500))
                        .is_ok()
                })
            })
            .unwrap_or(false);
        if reachable {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if var("MESON_RUSTFS_ALLOW_UNREACHABLE").as_deref() == Some("1") {
        eprintln!("skip {scenario}: {endpoint} unreachable (MESON_RUSTFS_ALLOW_UNREACHABLE=1)");
        return false;
    }
    // Unreachable and not allowed: run on so the real connection error surfaces.
    true
}
