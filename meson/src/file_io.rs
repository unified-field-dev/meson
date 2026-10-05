//! Product File IO helpers: upload bytes + metadata, load bytes from a File row.
//!
//! Hosts install a store with [`crate::install_blob_store`]. Product code then
//! uses [`FileUpload::create_with_bytes`] (System Valence — File create stays
//! `SYSTEM_ONLY`) and [`FileBytes::get_file_bytes`] after a session
//! [`valence::Model::get`].

use crate::backend::keys::validate_object_key;
use crate::blob_install::{installed_blob_store, installed_quarantine_store};
use crate::generated::{FileFields, FileFileStatus};
use crate::scan_kickoff;
use crate::virus_scan_config::virus_scan_enabled;
use crate::FileStoreError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::future::Future;
use thiserror::Error;
use uuid::Uuid;
use valence::connection::IdHolder;
use valence::{Model, RecordId, Valence};

/// Caller-supplied metadata for [`FileUpload::create_with_bytes`].
///
/// Does not include `storage_path`, `size_bytes`, or `file_status` — those are
/// filled by the helper after a successful put.
#[derive(Debug, Clone)]
pub struct FileCreateMeta {
    /// Original display name (for example `receipt-1.png`).
    pub file_name: String,
    /// Flat extension without a leading dot (for example `png`). Rejected when
    /// empty or containing path separators / `..`.
    pub file_extension: String,
    /// MIME type (for example `image/png`).
    pub mime_type: String,
    /// Soft owner reference (`user` RecordId).
    pub uploaded_by: RecordId,
}

/// Errors from [`FileUpload::create_with_bytes`] and [`put_new_object`].
#[derive(Debug, Error)]
pub enum FileUploadError {
    /// Host has not called [`crate::install_blob_store`].
    #[error("blob store not installed")]
    BlobStoreNotInstalled,
    /// Extension empty or unsafe for a flat object key.
    #[error("invalid file extension")]
    InvalidExtension,
    /// Blob store put/get failure.
    #[error(transparent)]
    Store(#[from] FileStoreError),
    /// Valence create / model construction failed (blob may already exist).
    #[error(transparent)]
    Valence(#[from] valence::Error),
}

impl FileUploadError {
    fn from_install(err: FileStoreError) -> Self {
        match err {
            FileStoreError::BlobStoreNotInstalled | FileStoreError::QuarantineStoreNotInstalled => {
                Self::BlobStoreNotInstalled
            }
            other => Self::Store(other),
        }
    }
}

/// Result of putting bytes under a newly generated flat key.
#[derive(Debug, Clone)]
pub struct PutObjectResult {
    /// Flat object key written to the installed store (`{uuid}.{ext}`).
    pub storage_path: String,
    /// Byte length written.
    pub size_bytes: i64,
}

/// Validate `extension`, generate `{uuid}.{ext}`, and put `bytes` on the
/// appropriate store.
///
/// When [`virus_scan_enabled`] is true, bytes go to the **quarantine** store.
/// When `MESON_VIRUS_SCAN=off`, bytes go to the **available** store.
///
/// Use this when the File model needs extra constructor args (for example a
/// profile FK) that [`FileUpload::create_with_bytes`] cannot supply. Prefer
/// [`FileUpload::create_with_bytes`] for File-only models.
///
/// # Errors
///
/// Returns [`FileUploadError::BlobStoreNotInstalled`],
/// [`FileUploadError::InvalidExtension`], or store errors from put.
pub async fn put_new_object(
    extension: &str,
    bytes: &[u8],
) -> Result<PutObjectResult, FileUploadError> {
    let key = generate_storage_key(extension)?;
    let store = if virus_scan_enabled() {
        installed_quarantine_store().map_err(FileUploadError::from_install)?
    } else {
        installed_blob_store().map_err(FileUploadError::from_install)?
    };
    store.put(&key, bytes).await?;
    let size_bytes = i64::try_from(bytes.len()).map_err(|_| {
        FileUploadError::Store(FileStoreError::io_msg("file size does not fit i64"))
    })?;
    Ok(PutObjectResult {
        storage_path: key,
        size_bytes,
    })
}

fn initial_file_status() -> FileFileStatus {
    if virus_scan_enabled() {
        FileFileStatus::PendingVirusScan
    } else {
        FileFileStatus::Available
    }
}

/// Generate a flat `{uuid}.{ext}` key and validate it.
fn generate_storage_key(extension: &str) -> Result<String, FileUploadError> {
    let ext = extension.trim().trim_start_matches('.');
    if ext.is_empty()
        || ext.contains('/')
        || ext.contains('\\')
        || ext.contains("..")
        || ext.contains('.')
    {
        return Err(FileUploadError::InvalidExtension);
    }
    let key = format!("{}.{}", Uuid::new_v4(), ext);
    validate_object_key(&key).map_err(|_| FileUploadError::InvalidExtension)?;
    Ok(key)
}

/// Load opaque bytes for a File row from the installed blob store.
///
/// Call only on rows obtained from session [`Model::get`] or an owner-scoped
/// query. This method does not re-check Valence privacy.
///
/// Meson [`FileFields`] types get a blanket impl. Product models in other crates
/// implement [`Self::storage_path`] (one line) to use the same helper.
#[async_trait]
pub trait FileBytes: Sync {
    /// Opaque object key for the installed [`crate::FileByteBackend`].
    fn storage_path(&self) -> &str;

    /// Fetch bytes for [`Self::storage_path`].
    ///
    /// # Errors
    ///
    /// Returns [`FileStoreError::BlobStoreNotInstalled`] when the host has not
    /// installed a store, [`FileStoreError::NotFound`] when the object is
    /// missing, or other [`FileStoreError`] variants from the backend.
    async fn get_file_bytes(&self) -> Result<Vec<u8>, FileStoreError> {
        tracing::debug!(
            target: "meson.file_bytes",
            operation = "get_file_bytes",
            "loading file bytes"
        );
        let store = installed_blob_store()?;
        store.get(self.storage_path()).await
    }
}

#[async_trait]
impl<T: FileFields + Sync> FileBytes for T {
    fn storage_path(&self) -> &str {
        FileFields::storage_path(self).as_str()
    }

    async fn get_file_bytes(&self) -> Result<Vec<u8>, FileStoreError> {
        let status = FileFields::file_status(self);
        if !matches!(status, FileFileStatus::Available) {
            tracing::debug!(
                target: "meson.file_bytes",
                operation = "get_file_bytes",
                outcome = "not_available",
                file_status = %status,
                "refusing bytes for non-available file"
            );
            return Err(FileStoreError::NotAvailable {
                status: Some(status.as_str().to_string()),
            });
        }
        tracing::debug!(
            target: "meson.file_bytes",
            operation = "get_file_bytes",
            file_status = "available",
            "loading file bytes"
        );
        let store = installed_blob_store()?;
        store.get(FileFields::storage_path(self).as_str()).await
    }
}

/// Create a File-backed Valence row after putting bytes on the installed store.
///
/// Implement [`Self::from_stored_file`] for each concrete File model (generated
/// `new` arity differs by schema). [`Self::create_with_bytes`] is provided.
#[async_trait]
pub trait FileUpload: Sized + Model + Send {
    /// Build a row after bytes are stored (fills File fields from `meta` + put).
    ///
    /// Models with extra fields (width, profile FK, …) bake defaults or require
    /// a custom upload entrypoint that calls [`put_new_object`] then `create`.
    fn from_stored_file(
        meta: FileCreateMeta,
        storage_path: String,
        size_bytes: i64,
        file_status: FileFileStatus,
        uploaded_at: DateTime<Utc>,
    ) -> Result<Self, FileUploadError>;

    /// Put `bytes`, then [`Model::create`] under `valence` (typically System —
    /// File create stays `SYSTEM_ONLY`).
    ///
    /// When scanning is on the row starts `PendingVirusScan` and Meson enqueues
    /// the `meson_virus_scan` Boson task for it (`scan-boson` feature). Enqueue
    /// problems are logged and leave the row Pending; they never fail the create.
    ///
    /// # Errors
    ///
    /// Returns install / extension / store errors before create. When put
    /// succeeds and Valence create fails, the blob may remain (orphan); the
    /// error is [`FileUploadError::Valence`].
    async fn create_with_bytes(
        valence: &Valence,
        meta: FileCreateMeta,
        bytes: &[u8],
    ) -> Result<Self, FileUploadError>
    where
        Self: IdHolder,
    {
        let put = put_new_object(&meta.file_extension, bytes).await?;
        let size_bytes = put.size_bytes;
        let status = initial_file_status();
        let pending = matches!(status, FileFileStatus::PendingVirusScan);
        let status_label = status.as_str();
        let row = Self::from_stored_file(meta, put.storage_path, size_bytes, status, Utc::now())?;
        match Self::create(row, valence, valence::use_!(r"In **Meson file storage**, we **save this data** so the product can continue this workflow with durable state. People and services allowed for **Meson file storage** rely on this record for that step—not as a dump of every personal field.")).await {
            Ok(created) => {
                tracing::info!(
                    target: "meson.file_upload",
                    operation = "create_with_bytes",
                    outcome = "ok",
                    size_bytes,
                    file_status = status_label,
                    "file uploaded"
                );
                if pending {
                    scan_kickoff::kick_off(
                        "create_with_bytes",
                        Self::table_name(),
                        created.record_id(),
                    )
                    .await;
                }
                Ok(created)
            }
            Err(err) => {
                tracing::warn!(
                    target: "meson.file_upload",
                    operation = "create_with_bytes",
                    outcome = "create_failed_after_put",
                    size_bytes,
                    "Valence create failed after blob put; blob may remain"
                );
                Err(FileUploadError::Valence(err))
            }
        }
    }
}

/// Fetch bytes for `storage_path` from the installed blob store.
///
/// Prefer [`FileBytes::get_file_bytes`] on File rows in the same crate. Cross-crate
/// models (orphan-rule) call this with their inherent `storage_path()`.
///
/// # Errors
///
/// Same as [`FileBytes::get_file_bytes`].
pub async fn get_installed_object(storage_path: &str) -> Result<Vec<u8>, FileStoreError> {
    let store = installed_blob_store()?;
    store.get(storage_path).await
}

/// Put bytes then build + create a File model via a caller-supplied constructor.
///
/// Prefer [`FileUpload::create_with_bytes`] when the model implements
/// [`FileUpload`]. Use this for schemas with extra fields (profile FK, …).
///
/// `build` receives the File status to store: `PendingVirusScan` when scanning
/// is on, `Available` otherwise. Pending rows get the same automatic
/// `meson_virus_scan` enqueue as [`FileUpload::create_with_bytes`].
///
/// # Errors
///
/// Same classes as [`FileUpload::create_with_bytes`].
pub async fn create_with_put<M, F, Fut>(
    valence: &Valence,
    meta: FileCreateMeta,
    bytes: &[u8],
    build: F,
) -> Result<M, FileUploadError>
where
    M: Model + IdHolder + Send,
    F: FnOnce(FileCreateMeta, String, i64, FileFileStatus, DateTime<Utc>) -> Fut + Send,
    Fut: Future<Output = Result<M, FileUploadError>> + Send,
{
    let put = put_new_object(&meta.file_extension, bytes).await?;
    let size_bytes = put.size_bytes;
    let status = initial_file_status();
    let pending = matches!(status, FileFileStatus::PendingVirusScan);
    let status_label = status.as_str();
    let row = build(meta, put.storage_path, size_bytes, status, Utc::now()).await?;
    match M::create(row, valence, valence::use_!(r"When **Meson file storage** needs to persist work, we **save M** so the next step in that feature can continue with the latest values. People and services allowed for **Meson file storage** use this data for that workflow—not as a general export of unrelated personal fields.")).await {
        Ok(created) => {
            tracing::info!(
                target: "meson.file_upload",
                operation = "create_with_put",
                outcome = "ok",
                size_bytes,
                file_status = status_label,
                "file uploaded"
            );
            if pending {
                scan_kickoff::kick_off("create_with_put", M::table_name(), created.record_id())
                    .await;
            }
            Ok(created)
        }
        Err(err) => {
            tracing::warn!(
                target: "meson.file_upload",
                operation = "create_with_put",
                outcome = "create_failed_after_put",
                size_bytes,
                "Valence create failed after blob put; blob may remain"
            );
            Err(FileUploadError::Valence(err))
        }
    }
}

#[async_trait]
impl FileUpload for crate::generated::E2eMesonFile {
    fn from_stored_file(
        meta: FileCreateMeta,
        storage_path: String,
        size_bytes: i64,
        file_status: FileFileStatus,
        uploaded_at: DateTime<Utc>,
    ) -> Result<Self, FileUploadError> {
        Self::new(
            meta.file_name,
            meta.file_extension,
            meta.mime_type,
            size_bytes,
            storage_path,
            file_status,
            meta.uploaded_by,
            uploaded_at,
        )
        .map_err(FileUploadError::Valence)
    }
}

#[async_trait]
impl FileUpload for crate::generated::E2eMesonProfilePhoto {
    fn from_stored_file(
        meta: FileCreateMeta,
        storage_path: String,
        size_bytes: i64,
        file_status: FileFileStatus,
        uploaded_at: DateTime<Utc>,
    ) -> Result<Self, FileUploadError> {
        Self::new(
            None,
            None,
            meta.file_name,
            meta.file_extension,
            meta.mime_type,
            size_bytes,
            storage_path,
            file_status,
            meta.uploaded_by,
            uploaded_at,
        )
        .map_err(FileUploadError::Valence)
    }
}

#[async_trait]
impl FileUpload for crate::generated::ReceiptScan {
    fn from_stored_file(
        meta: FileCreateMeta,
        storage_path: String,
        size_bytes: i64,
        file_status: FileFileStatus,
        uploaded_at: DateTime<Utc>,
    ) -> Result<Self, FileUploadError> {
        Self::new(
            meta.file_name,
            meta.file_extension,
            meta.mime_type,
            size_bytes,
            storage_path,
            file_status,
            meta.uploaded_by,
            uploaded_at,
        )
        .map_err(FileUploadError::Valence)
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn generate_storage_key_flat() {
        let key = generate_storage_key("png").expect("key");
        assert!(key.contains('.'));
        assert!(!key.contains('/'));
        assert!(validate_object_key(&key).is_ok());
        let ext = key.rsplit('.').next().expect("ext");
        assert_eq!(ext, "png");
    }

    #[test]
    fn generate_storage_key_rejects_bad_ext() {
        assert!(matches!(
            generate_storage_key(""),
            Err(FileUploadError::InvalidExtension)
        ));
        assert!(matches!(
            generate_storage_key("a/b"),
            Err(FileUploadError::InvalidExtension)
        ));
        assert!(matches!(
            generate_storage_key(".."),
            Err(FileUploadError::InvalidExtension)
        ));
        assert!(matches!(
            generate_storage_key("tar.gz"),
            Err(FileUploadError::InvalidExtension)
        ));
    }
}
