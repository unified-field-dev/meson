//! Process-wide [`FileByteBackend`] installs for available and quarantine stores.
//!
//! Hosts call [`install_blob_store`] (available) and [`install_quarantine_store`]
//! once at boot (typically from [`crate::blob_stores_from_env`]). File helpers
//! and promote use those installs. Tests use the `clear_*_for_test` helpers
//! between cases.

use crate::backend::FileByteBackend;
use crate::FileStoreError;
use std::sync::{Arc, Mutex, OnceLock};

static AVAILABLE: OnceLock<Mutex<Option<Arc<dyn FileByteBackend>>>> = OnceLock::new();
static QUARANTINE: OnceLock<Mutex<Option<Arc<dyn FileByteBackend>>>> = OnceLock::new();

fn available_slot() -> &'static Mutex<Option<Arc<dyn FileByteBackend>>> {
    AVAILABLE.get_or_init(|| Mutex::new(None))
}

fn quarantine_slot() -> &'static Mutex<Option<Arc<dyn FileByteBackend>>> {
    QUARANTINE.get_or_init(|| Mutex::new(None))
}

/// Install the process-wide **available** blob store used by File load helpers.
///
/// Call once at host boot. Later calls replace the previous install (hosts that
/// reconfigure in tests should prefer [`clear_blob_store_for_test`] then
/// install again).
///
/// # Errors
///
/// This function does not fail today; the `Result` is reserved for future
/// validation of the installed backend.
pub fn install_blob_store(store: Arc<dyn FileByteBackend>) -> Result<(), FileStoreError> {
    let mut guard = available_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(store);
    tracing::info!(
        target: "meson.blob_store",
        outcome = "installed",
        store = "available",
        "blob store installed for File IO helpers"
    );
    Ok(())
}

/// Return the installed available blob store, or [`FileStoreError::BlobStoreNotInstalled`].
///
/// # Errors
///
/// Returns [`FileStoreError::BlobStoreNotInstalled`] when no host has called
/// [`install_blob_store`].
pub fn installed_blob_store() -> Result<Arc<dyn FileByteBackend>, FileStoreError> {
    let guard = available_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.clone().ok_or(FileStoreError::BlobStoreNotInstalled)
}

/// Clear the process-wide **available** install (integration tests only).
pub fn clear_blob_store_for_test() {
    let mut guard = available_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Install the process-wide **quarantine** blob store (pre-scan bytes).
///
/// # Errors
///
/// This function does not fail today; the `Result` is reserved for future
/// validation of the installed backend.
pub fn install_quarantine_store(store: Arc<dyn FileByteBackend>) -> Result<(), FileStoreError> {
    let mut guard = quarantine_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(store);
    tracing::info!(
        target: "meson.blob_store",
        outcome = "installed",
        store = "quarantine",
        "quarantine store installed for File IO helpers"
    );
    Ok(())
}

/// Return the installed quarantine store, or [`FileStoreError::QuarantineStoreNotInstalled`].
///
/// # Errors
///
/// Returns [`FileStoreError::QuarantineStoreNotInstalled`] when no host has called
/// [`install_quarantine_store`].
pub fn installed_quarantine_store() -> Result<Arc<dyn FileByteBackend>, FileStoreError> {
    let guard = quarantine_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .clone()
        .ok_or(FileStoreError::QuarantineStoreNotInstalled)
}

/// Clear the process-wide quarantine install (integration tests only).
pub fn clear_quarantine_store_for_test() {
    let mut guard = quarantine_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Clear both available and quarantine installs (integration tests only).
pub fn clear_blob_stores_for_test() {
    clear_blob_store_for_test();
    clear_quarantine_store_for_test();
}

/// Serialize process-wide blob install mutations across unit tests in this crate.
#[cfg(test)]
pub async fn blob_stores_unit_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalDiskBlobStore;

    #[tokio::test]
    async fn install_and_clear_available_round_trip() {
        let _g = blob_stores_unit_test_lock().await;
        clear_blob_stores_for_test();
        assert!(matches!(
            installed_blob_store(),
            Err(FileStoreError::BlobStoreNotInstalled)
        ));
        install_blob_store(Arc::new(LocalDiskBlobStore::new(std::env::temp_dir()))).unwrap();
        assert!(installed_blob_store().is_ok());
        clear_blob_store_for_test();
        assert!(matches!(
            installed_blob_store(),
            Err(FileStoreError::BlobStoreNotInstalled)
        ));
    }

    #[tokio::test]
    async fn install_and_clear_quarantine_round_trip() {
        let _g = blob_stores_unit_test_lock().await;
        clear_blob_stores_for_test();
        assert!(matches!(
            installed_quarantine_store(),
            Err(FileStoreError::QuarantineStoreNotInstalled)
        ));
        install_quarantine_store(Arc::new(LocalDiskBlobStore::new(std::env::temp_dir()))).unwrap();
        assert!(installed_quarantine_store().is_ok());
        clear_quarantine_store_for_test();
        assert!(matches!(
            installed_quarantine_store(),
            Err(FileStoreError::QuarantineStoreNotInstalled)
        ));
    }
}
