//! Meson stores File metadata in Valence and opaque bytes behind a host-installed
//! [`FileByteBackend`]. Product code uploads with [`FileUpload::create_with_bytes`]
//! and loads with session [`valence::Model::get`] plus [`FileBytes::get_file_bytes`].
//! Hosts call [`install_blob_store`] once at boot (often via [`blob_store_from_env`]).
//!
//! Valence is Unified Field's typed data layer: a `File` schema holds metadata
//! (`file_name`, `mime_type`, `storage_path`, …); Meson stores the bytes.
//!
//! # Features
//!
//! - **File trait** — Shared metadata (`file_name`, `mime_type`, `storage_path`,
//!   `uploaded_by`, …) for uploadable objects. Opt in with `traits: [File]` on a
//!   concrete schema (vendor this crate's trait file under your `schemas/` for
//!   codegen). [Get started](#opt-in-file-trait)
//! - **File upload** — Put bytes and create a File row in one call via
//!   [`FileUpload::create_with_bytes`] (System Valence; File create stays
//!   `SYSTEM_ONLY`). With scanning on, the row starts `PendingVirusScan` and
//!   Meson enqueues its scan. [Get started](#upload-file-bytes)
//! - **File bytes** — Load opaque bytes from a File row with
//!   [`FileBytes::get_file_bytes`] after a session get. [Get started](#load-file-bytes)
//! - **Blob store** — Process-wide [`install_blob_store`] so File helpers resolve
//!   the host backend without a store argument on every call.
//!   [Get started](#install-blob-store)
//! - **Byte backend** — Put, get, and delete opaque object keys for host wiring
//!   and low-level stores. Embedded hosts use [`LocalDiskBlobStore`]; remote hosts
//!   use [`RustFsBlobStore`] (`backend-rustfs`). [Get started](#store-bytes-on-local-disk)
//! - **Env blob store** — Build `Arc<dyn FileByteBackend>` from `MESON_*` env
//!   (`local` or `rustfs`) so hosts select a backend from process config.
//!   [Get started](#select-blob-store-from-env)
//! - **My uploads query** — Cross-table list filtered by `uploaded_by` via
//!   [`generated::FileQueryAll`] (My Files union). [Get started](#list-uploads-with-filequeryall)
//! - **Preview kind** — Classify mime types for image/text/unsupported routing
//!   via [`preview_kind`]. [API reference](preview/enum.PreviewKind.html)
//! - **Virus quarantine** — Dual stores (`install_quarantine_store` + available),
//!   quarantine-first upload when scan is on, [`promote_to_available`] after a
//!   clean scan. Opt out with `MESON_VIRUS_SCAN=off`.
//!   [Get started](#install-dual-blob-stores)
//! - **Scan adapters** — Each product File table registers a
//!   [`FileScanAdapter`] so the scan task can load the row and commit its
//!   verdict. [Get started](#register-a-scan-adapter)
//! - **Virus scan enqueue** — Uploads enqueue their own scan. Call
//!   [`enqueue_virus_scan`] to start one again for a row that is still
//!   Pending. [Get started](#enqueue-a-virus-scan)
//! - **File readiness** — [`wait_until_available`] / [`get_available_file_bytes`]
//!   gate processors on Available (never quarantine bytes).
//!   [Get started](#wait-until-file-available)
//!
//! # Opt in File trait
//!
//! File is the Valence trait Meson owns for upload metadata. Products declare it
//! on concrete tables so `FileQueryAll` can union those rows. Hosts and sibling
//! crates must vendor `schemas/file_valence_trait.rs` locally for codegen
//! (Valence accepts bare `traits: [File]` only).
//!
//! Prerequisites: `meson` (or a vendored copy of the File trait) on the path;
//! Valence codegen wired to your `schemas/` directory.
//!
//! 1. Copy `file_valence_trait.rs` into the consuming crate's `schemas/`.
//! 2. On a concrete `valence_schema!`, set `traits: [File]`.
//! 3. Rebuild so codegen emits File fields on the model and registers the table
//!    with the File trait union.
//!
//! ```rust,ignore
//! use valence::prelude::*;
//!
//! valence_schema! {
//!     ReceiptScan {
//!         table: "receipt_scan",
//!         version: "0.1.0",
//!         database: /* host storage evaluator */,
//!         description: "Uploaded receipt image",
//!         traits: [File],
//!         policies: { /* … */ },
//!         fields: [
//!             id: {
//!                 r#type: FieldType::String,
//!                 primary_key: true,
//!                 required: true,
//!             },
//!         ],
//!     }
//! }
//!
//! // After codegen, ReceiptScan implements FileFields and joins FileQueryAll.
//! use meson::generated::FileFields;
//! fn assert_file_fields<T: FileFields>() {}
//! assert_file_fields::<ReceiptScan>();
//! assert!(!std::any::type_name::<ReceiptScan>().is_empty());
//! ```
//!
//! On success the table participates in [`generated::FileQueryAll`]. Missing the
//! vendored trait file fails codegen. Soft `uploaded_by` points at `user` via a
//! codegen stub so Meson stays free of a typed User model.
//!
//! **Next:** [Install blob store](#install-blob-store), then
//! [upload file bytes](#upload-file-bytes).
//!
//! # Install blob store
//!
//! [`install_blob_store`] registers one `Arc<dyn FileByteBackend>` for the process
//! so [`FileUpload`] and [`FileBytes`] resolve storage without a store argument.
//! Call once at host boot (SSR worker, Axum binary). Tests call
//! [`clear_blob_store_for_test`] between cases.
//!
//! Prerequisites: a backend from [`blob_store_from_env`] or
//! [`LocalDiskBlobStore`] / [`RustFsBlobStore`].
//!
//! 1. Build the store from env or an explicit constructor.
//! 2. Call [`install_blob_store`] once at startup.
//! 3. Use File upload / load helpers from product code.
//!
//! ```rust,no_run
//! use meson::{blob_store_from_env, install_blob_store};
//!
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! install_blob_store(blob_store_from_env()?)?;
//! # Ok(())
//! # }
//! ```
//!
//! On success later [`FileBytes::get_file_bytes`] and
//! [`FileUpload::create_with_bytes`] use that install. Calling helpers before
//! install returns [`FileStoreError::BlobStoreNotInstalled`] /
//! [`FileUploadError::BlobStoreNotInstalled`].
//!
//! **Next:** [Upload file bytes](#upload-file-bytes).
//!
//! # Upload file bytes
//!
//! [`FileUpload::create_with_bytes`] generates a flat `{uuid}.{ext}` key, puts
//! bytes on the installed store, then creates the Valence File row (size,
//! `uploaded_at`, scan status). File create stays `SYSTEM_ONLY` — pass System
//! Valence from the host upload path. Session actors stay on the load path.
//!
//! Scanning is on unless `MESON_VIRUS_SCAN=off`. With it on, the bytes go to the
//! quarantine store, the row starts `PendingVirusScan`, and Meson enqueues
//! `meson_virus_scan` for it. Readers wait for Available
//! ([Wait until File Available](#wait-until-file-available)). With it off, the
//! row is `Available` right away and nothing is enqueued.
//!
//! Prerequisites: [`install_blob_store`] (plus [`install_quarantine_store`] when
//! scanning is on); a File model that implements [`FileUpload`] (teaching type
//! [`ReceiptScan`], or your schema's `from_stored_file`); a registered
//! [scan adapter](#register-a-scan-adapter) and a configured Boson runtime for
//! the scan to start.
//!
//! 1. Install the blob stores at boot.
//! 2. Under System Valence, call `create_with_bytes` with [`FileCreateMeta`] and bytes.
//! 3. Keep the returned row id for later session load.
//!
//! ```rust,ignore
//! use meson::{FileCreateMeta, FileFileStatus, FileUpload, ReceiptScan};
//! use valence::RecordId;
//!
//! async fn add_receipt(
//!     system_v: &valence::Valence,
//!     owner: RecordId,
//!     bytes: &[u8],
//! ) -> Result<ReceiptScan, meson::FileUploadError> {
//!     let created = ReceiptScan::create_with_bytes(
//!         system_v,
//!         FileCreateMeta {
//!             file_name: "receipt-1.png".into(),
//!             file_extension: "png".into(),
//!             mime_type: "image/png".into(),
//!             uploaded_by: owner,
//!         },
//!         bytes,
//!     )
//!     .await?;
//!     assert!(created.id().is_some());
//!     // Scanning is on, so the row waits for the scan Meson just enqueued.
//!     assert_eq!(created.file_status(), &FileFileStatus::PendingVirusScan);
//!     Ok(created)
//! }
//! ```
//!
//! On success the row is persisted. With scanning off the bytes are readable
//! via [`FileBytes::get_file_bytes`] at once; with it on, read them through
//! [`get_available_file_bytes`] after the scan marks the row Available.
//! Invalid extensions return [`FileUploadError::InvalidExtension`]. When put
//! succeeds and Valence create fails, the blob may remain (orphan). If the scan
//! can't be enqueued (no Boson, no adapter), create still succeeds and the row
//! stays Pending; Meson logs `outcome="scan_enqueue_failed"` or
//! `outcome="no_scan_adapter"` under target `meson.file_upload`.
//!
//! **Next:** [Load file bytes](#load-file-bytes). Runnable:
//! `cargo run -p meson --example upload_and_load`.
//!
//! # Load file bytes
//!
//! After session [`valence::Model::get`] returns a File row, call
//! [`FileBytes::get_file_bytes`]. Authz is the Valence get (or an owner-scoped
//! query). The helper reads the installed store and does not re-check privacy.
//!
//! Prerequisites: installed blob store; a File row from session Valence.
//!
//! 1. `Model::get` (or owner-scoped query) under the session actor.
//! 2. On `Some(row)`, call `get_file_bytes`.
//! 3. Treat missing / foreign rows as not found before touching bytes.
//!
//! ```rust,ignore
//! use meson::{FileBytes, ReceiptScan};
//! use valence::Model;
//!
//! async fn load_receipt(
//!     session_v: &valence::Valence,
//!     bare_id: &str,
//! ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//!     let row = ReceiptScan::get(bare_id, session_v, valence::use_!(r"In **Meson file storage**, we **load Receipt Scan** so the application can decide what to do next in this workflow. The result is used by **Meson file storage** logic—not necessarily displayed on a page unless that feature’s UI shows it.")).await?.ok_or("not found")?;
//!     let bytes = row.get_file_bytes().await?;
//!     assert_eq!(bytes, b"PNG..");
//!     Ok(bytes)
//! }
//! ```
//!
//! On success bytes match the uploaded payload. Missing objects return
//! [`FileStoreError::NotFound`]. My Files list/preview across many File tables
//! still uses [`find_file_in_owned_rows`] after [`generated::FileQueryAll`].
//!
//! **Next:** [List uploads with FileQueryAll](#list-uploads-with-filequeryall)
//! for the My Files union, or run `cargo run -p meson --example upload_and_load`.
//!
//! # Store bytes on local disk
//!
//! [`LocalDiskBlobStore`] keeps object bytes beside Valence metadata. Prefer
//! [`FileUpload`] / [`FileBytes`] for product paths. Use put/get directly when
//! wiring hosts or debugging keys.
//!
//! Prerequisites: this crate on the path; a writable directory for the store.
//!
//! 1. Build a [`LocalDiskBlobStore`] (or any [`FileByteBackend`]).
//! 2. Call [`FileByteBackend::put`] with a flat object key (no path separators).
//! 3. Call [`FileByteBackend::get`] and assert the returned bytes.
//!
//! ```rust,no_run
//! use meson::{FileByteBackend, LocalDiskBlobStore};
//! use std::sync::Arc;
//!
//! # async fn demo() -> Result<(), meson::FileStoreError> {
//! let store: Arc<dyn FileByteBackend> = Arc::new(LocalDiskBlobStore::default_uploads());
//! store.put("abc.png", b"PNG..").await?;
//! let bytes = store.get("abc.png").await?;
//! assert_eq!(bytes, b"PNG..");
//! # Ok(())
//! # }
//! ```
//!
//! On success the key is readable until deleted. Invalid keys (`..`, `/`) return
//! [`FileStoreError::InvalidKey`]. Missing keys return [`FileStoreError::NotFound`].
//!
//! **Next:** [Select blob store from env](#select-blob-store-from-env), then
//! [install blob store](#install-blob-store).
//!
//! # Select blob store from env
//!
//! [`blob_store_from_env`] builds an `Arc<dyn FileByteBackend>` from process env
//! so SSR hosts pick LocalDisk or RustFS from `MESON_*` at boot. Pass the result
//! to [`install_blob_store`].
//!
//! Prerequisites: enable the Cargo features for backends you might select
//! (`backend-local`, and `backend-rustfs` when `MESON_BLOB_BACKEND=rustfs`). Set
//! `MESON_BLOB_BACKEND` to `local` or `rustfs`. For rustfs also set
//! `MESON_RUSTFS_ENDPOINT`, `MESON_RUSTFS_BUCKET`, `MESON_RUSTFS_ACCESS_KEY`, and
//! `MESON_RUSTFS_SECRET_KEY` (optional `MESON_RUSTFS_REGION`, default `us-east-1`).
//! For local, optional `MESON_LOCAL_ROOT` (default `uploads`).
//!
//! 1. Export `MESON_BLOB_BACKEND` (and RustFS vars when using rustfs).
//! 2. Call [`blob_store_from_env`] once at host startup.
//! 3. [`install_blob_store`] the returned `Arc` (and optionally `provide_context`
//!    the same Arc for legacy Leptos seams).
//! 4. Put and get a flat key to confirm the store, or use File upload helpers.
//!
//! ```rust,no_run
//! use meson::{blob_store_from_env, install_blob_store, FileByteBackend};
//! use std::sync::Arc;
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! // Host env: MESON_BLOB_BACKEND=local|rustfs (+ MESON_RUSTFS_* for rustfs).
//! let store: Arc<dyn FileByteBackend> = blob_store_from_env()?;
//! install_blob_store(Arc::clone(&store))?;
//! store.put("abc.png", b"PNG..").await?;
//! let bytes = store.get("abc.png").await?;
//! assert_eq!(bytes, b"PNG..");
//! # Ok(())
//! # }
//! ```
//!
//! On success the selected backend serves put/get like any [`FileByteBackend`].
//! Missing env or an unknown backend name returns [`BlobStoreConfigError`].
//! RustFS auth failures map to [`FileStoreError::Unauthorized`].
//!
//! **Next:** [Upload file bytes](#upload-file-bytes), then
//! [list uploads](#list-uploads-with-filequeryall).
//!
//! # List uploads with FileQueryAll
//!
//! `FileQueryAll` provides a cross-table view of every linked File implementor.
//! My Files binds `uploaded_by` to the session user RecordId so the list stays
//! owner-scoped. Never forge another user's id in the filter. Typed product load
//! prefers `YourFile::get` + [`FileBytes::get_file_bytes`]; use
//! [`find_file_in_owned_rows`] when the UI holds a bare id across many tables.
//!
//! Prerequisites: host links Meson and every File-bearing schema crate; a
//! signed-in session [`valence::Valence`] for the viewer (Higgs session actor).
//!
//! 1. Build session Valence from Higgs (or equivalent).
//! 2. Query [`generated::FileQueryAll`] with `where_uploaded_by` Equals session user.
//! 3. Optionally [`find_file_in_owned_rows`] for a detail/preview id.
//!
//! ```rust,ignore
//! use meson::generated::{FileFields, FileQueryAll};
//! use meson::find_file_in_owned_rows;
//! use valence::{RecordId, RecordPredicate};
//!
//! async fn list_mine(
//!     v: &valence::Valence,
//!     user: RecordId,
//! ) -> valence::Result<Vec<meson::generated::FileModel>> {
//!     let rows = FileQueryAll::query(v, valence::use_!(r"In **Meson file storage**, we **list File Query All** so the product can show or process the matching set for this workflow. Callers allowed for **Meson file storage** use the list; it is not a public dump of every field to anonymous visitors."))
//!         .where_uploaded_by(RecordPredicate::Equals(user.clone()))
//!         .await?;
//!     assert!(rows.iter().all(|r| r.uploaded_by() == &user));
//!     Ok(rows)
//! }
//!
//! async fn get_mine(
//!     v: &valence::Valence,
//!     user: RecordId,
//!     want: RecordId,
//! ) -> Option<meson::generated::FileModel> {
//!     let rows = list_mine(v, user).await.ok()?;
//!     find_file_in_owned_rows(rows, &want)
//! }
//! ```
//!
//! On success the vector contains only that user's File rows across linked tables.
//! A missing or foreign id yields `None` from [`find_file_in_owned_rows`]
//! (treat as not found — same response shape for missing and foreign rows).
//!
//! # Feature flags
//!
//! | Flag | Purpose |
//! |------|---------|
//! | `db-sqlite` (default) | Valence sqlite backend feature |
//! | `db-hybrid` | Valence hybrid backend feature |
//! | `backend-local` (default) | [`LocalDiskBlobStore`] |
//! | `backend-rustfs` | [`RustFsBlobStore`] (S3 path-style / RustFS) |
//! | `scan-pipeline` | Boson task + Photon `meson.file.updated`; Pending uploads enqueue their own scan |
//! | `scan-chronon` | Chronon `meson_virus_scan_sweeper` |
//! | `scanner-clamav` | ClamAV INSTREAM scanner (`ClamAvScanner`) |
//!
//! Runtime selection: [Select blob store from env](#select-blob-store-from-env)
//! (`MESON_BLOB_BACKEND=local|rustfs` and related `MESON_*` vars). Quarantine
//! roots: `MESON_LOCAL_QUARANTINE_ROOT` / `MESON_RUSTFS_QUARANTINE_BUCKET`.
//!
//! # Install dual blob stores
//!
//! Hosts install both the available store and the quarantine store at boot.
//! [`blob_stores_from_env`] returns a [`BlobStoreLayout`] when quarantine env
//! is configured.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use meson::{
//!     blob_stores_from_env, install_blob_store, install_quarantine_store,
//!     install_virus_scanner, AlwaysCleanScanner, LocalDiskBlobStore,
//! };
//!
//! fn boot() -> Result<(), Box<dyn std::error::Error>> {
//!     let layout = blob_stores_from_env().unwrap_or_else(|_| meson::BlobStoreLayout {
//!         available: Arc::new(LocalDiskBlobStore::default_uploads()),
//!         quarantine: Arc::new(LocalDiskBlobStore::new("uploads-quarantine")),
//!     });
//!     install_blob_store(layout.available)?;
//!     install_quarantine_store(layout.quarantine)?;
//!     install_virus_scanner(Arc::new(AlwaysCleanScanner));
//!     Ok(())
//! }
//! ```
//!
//! **Next:** [Register a scan adapter](#register-a-scan-adapter) for each
//! product File table.
//!
//! # Register a scan adapter
//!
//! The `meson_virus_scan` task only knows a File table by name. A
//! [`FileScanAdapter`] tells it how to load that table's row and how to commit
//! Available or Quarantined. Meson registers adapters for its own teaching
//! tables; every product File table registers its own, once at boot, before
//! the first upload. Uploads to a table with no adapter stay Pending and log
//! `outcome="no_scan_adapter"`.
//!
//! Prerequisites: a File schema in your crate; Valence access the scan task's
//! System actor can use for get and update on that table.
//!
//! 1. Implement [`FileScanAdapter`] for the table (load, commit Available,
//!    commit Quarantined).
//! 2. Call [`register_file_scan_adapter`] with the table name at host boot.
//! 3. Confirm with [`load_file_for_scan`], which returns the row's
//!    [`FileScanSnapshot`].
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use meson::{
//!     load_file_for_scan, register_file_scan_adapter, FileScanAdapter,
//!     FileScanAdapterError, FileScanSnapshot,
//! };
//! use valence::Valence;
//!
//! struct StatementFileAdapter;
//!
//! #[async_trait::async_trait]
//! impl FileScanAdapter for StatementFileAdapter {
//!     async fn load(&self, v: &Valence, id: &str) -> Result<FileScanSnapshot, FileScanAdapterError> {
//!         /* get the row, copy storage_path / file_status / uploaded_by */
//!     }
//!     async fn commit_available(&self, v: &Valence, id: &str, path: String) -> Result<(), FileScanAdapterError> {
//!         /* set storage_path = path and file_status = Available */
//!     }
//!     async fn commit_quarantined(&self, v: &Valence, id: &str) -> Result<(), FileScanAdapterError> {
//!         /* set file_status = Quarantined */
//!     }
//! }
//!
//! fn boot() {
//!     register_file_scan_adapter("statement_file", Arc::new(StatementFileAdapter));
//! }
//!
//! async fn check(v: &Valence, id: &str) -> Result<(), FileScanAdapterError> {
//!     let snap = load_file_for_scan(v, "statement_file", id).await?;
//!     assert!(!snap.storage_path.is_empty());
//!     Ok(())
//! }
//! ```
//!
//! On success the scan task finds the row and commits its verdict. A table with
//! no adapter returns [`FileScanAdapterError::UnknownTable`]; a missing row
//! returns [`FileScanAdapterError::NotFound`]. Registering the same table again
//! replaces the earlier adapter.
//!
//! **Next:** [Wait until File Available](#wait-until-file-available) before
//! reading bytes.
//!
//! # Enqueue a virus scan
//!
//! Uploads through [`FileUpload::create_with_bytes`] and [`create_with_put`]
//! enqueue their own scan. Call [`enqueue_virus_scan`] yourself to start a scan
//! again for a row that is still `PendingVirusScan`, for example one created
//! while Boson was down. The `meson_virus_scan_sweeper` Chronon script
//! (`scan-chronon`) does the same for Pending rows older than `max_age_secs`
//! (default 300) when a host runs it. Enqueueing twice is
//! safe: both use the key `virus_scan:{table}:{id}`, and the task skips rows that
//! already finished.
//!
//! ```rust,ignore
//! use meson::enqueue_virus_scan;
//!
//! async fn rescan(table: &str, bare_id: &str) -> Result<(), meson::EnqueueScanError> {
//!     enqueue_virus_scan(table, bare_id).await?;
//!     Ok(())
//! }
//! ```
//!
//! On success Boson scans the row and publishes Photon `meson.file.updated`.
//! Without a configured Boson runtime you get
//! [`EnqueueScanError::BosonNotConfigured`]. Requires the `scan-pipeline` (or
//! `scan-boson`) feature.
//!
//! # Wait until File Available
//!
//! Processors (OCR, Chronon scripts, product workers) must read only Available
//! File bytes. Poll Valence until status is Available, then load from the
//! available store. Quarantined status returns [`ReadinessError::NotAvailable`].
//!
//! ```rust,ignore
//! use meson::{get_available_file_bytes, wait_until_available};
//! use std::time::Duration;
//!
//! async fn process(table: &str, id: &str, v: &valence::Valence) -> Result<Vec<u8>, meson::ReadinessError> {
//!     wait_until_available(v, table, id, Duration::from_secs(30)).await?;
//!     get_available_file_bytes(v, table, id).await
//! }
//! ```
//!
//! On timeout you get [`ReadinessError::Timeout`]. Prefer Photon
//! `meson.file.updated` for UI refetch; this wait helper is for worker gates.
//!
//! # Examples
//!
//! ```bash
//! CARGO_BUILD_JOBS=1 cargo run -p meson --example upload_and_load
//! # expect: ok uploaded+loaded 5 bytes
//! ```
//!
#![deny(missing_docs)]

pub mod backend;
mod blob_install;
pub mod embedded_surreal;
pub mod file_io;
pub mod file_scan_adapter;
pub mod generated;
pub mod ownership;
pub mod preview;
pub mod promote;
pub mod readiness;
pub mod scan;
mod scan_kickoff;
pub mod virus_scan_config;

#[cfg(feature = "photon")]
pub mod events;
#[cfg(not(feature = "photon"))]
pub mod events;

#[cfg(feature = "scan-boson")]
pub mod enqueue;
#[cfg(feature = "scan-boson")]
pub mod tasks;

#[cfg(feature = "scan-chronon")]
pub mod jobs;

mod schemas;

#[cfg(feature = "backend-local")]
pub use backend::LocalDiskBlobStore;
pub use backend::{
    blob_store_from_env, blob_stores_from_env, BlobStoreConfigError, BlobStoreLayout,
    FileByteBackend, FileStoreError,
};
#[cfg(feature = "backend-rustfs")]
pub use backend::{RustFsBlobStore, DEFAULT_RUSTFS_REGION};
pub use blob_install::{
    clear_blob_store_for_test, clear_blob_stores_for_test, clear_quarantine_store_for_test,
    install_blob_store, install_quarantine_store, installed_blob_store, installed_quarantine_store,
};
pub use file_io::{
    create_with_put, get_installed_object, put_new_object, FileBytes, FileCreateMeta, FileUpload,
    FileUploadError, PutObjectResult,
};
pub use file_scan_adapter::{
    clear_file_scan_adapters_for_test, commit_file_available, commit_file_quarantined,
    file_scan_adapter, load_file_for_scan, register_builtin_file_scan_adapters,
    register_file_scan_adapter, FileScanAdapter, FileScanAdapterError, FileScanSnapshot,
};
/// Teaching / inventory fixtures (`ReceiptScan`, `E2eMeson*`); product schemas live in consuming crates.
pub use generated::{E2eMesonFile, E2eMesonProfilePhoto, FileFileStatus, ReceiptScan};
pub use ownership::{find_file_in_owned_rows, is_uploaded_by};
pub use preview::{preview_kind, PreviewKind};
pub use promote::{promote_to_available, PromoteError};
pub use readiness::{
    ensure_readable_for_processing, get_available_file_bytes, wait_until_available,
    wait_until_available_object, ReadinessError,
};
pub use scan::{
    clear_virus_scanner_for_test, install_virus_scanner, installed_virus_scanner,
    resolve_virus_scanner, AlwaysCleanScanner, AlwaysInfectedScanner, ScanError, ScanVerdict,
    VirusScanner,
};
#[cfg(feature = "scanner-clamav")]
pub use scan::{parse_clamd_response, ClamAvConfigError, ClamAvScanner};
pub use virus_scan_config::virus_scan_enabled;

#[cfg(feature = "scan-boson")]
pub use enqueue::{enqueue_virus_scan, EnqueueScanError};

/// Keep e2e File fixture schema inventory linked for tests and hosts.
#[inline(never)]
pub fn touch_schema_inventory() {
    let _ = (
        std::any::type_name::<ReceiptScan>(),
        std::any::type_name::<E2eMesonFile>(),
        std::any::type_name::<E2eMesonProfilePhoto>(),
        std::any::type_name::<generated::E2eMesonSoftUser>(),
    );
    let _ = valence::TraitRegistry::global();
}

#[inline(never)]
fn ensure_schema_inventory_linked() {
    touch_schema_inventory();
}

#[used]
static __MESON_SCHEMA_INVENTORY: fn() = ensure_schema_inventory_linked;
