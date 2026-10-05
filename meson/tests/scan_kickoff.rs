//! Pending creates enqueue `meson_virus_scan` without a caller-side enqueue.
//!
//! Each test builds a step-driven Boson ([`ManualWorker`]) over the same Valence
//! router, creates a File row with scanning on, then drains the queue and checks
//! where the bytes ended up.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use boson_backend_mem::MemQueueBackend;
use boson_core::JobStatus;
use boson_runtime::{configure, Boson, ManualWorker};
use boson_valence_identity::{
    router_config_reject_external_system, ValenceExecutionContextFactory,
};
use chrono::{DateTime, Utc};
use meson::generated::{E2eMesonFile, FileFileStatus};
use meson::{
    clear_blob_stores_for_test, create_with_put, enqueue_virus_scan, get_available_file_bytes,
    install_blob_store, install_quarantine_store, install_virus_scanner, installed_blob_store,
    installed_quarantine_store, AlwaysCleanScanner, AlwaysInfectedScanner, FileCreateMeta,
    FileStoreError, FileUpload, FileUploadError, LocalDiskBlobStore, ReadinessError, VirusScanner,
};
use support::{blob_install_lock, owner_rid, setup_valence_with_router};
use valence::{ActorTrust, Model, RouterValenceFactory, Valence};

const TABLE: &str = "e2e_meson_file";

fn temp_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "meson-kickoff-{label}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

struct Harness {
    system: Valence,
    boson: Boson,
    worker: ManualWorker,
}

async fn harness(scanner: Arc<dyn VirusScanner>) -> Harness {
    // SAFETY: callers hold blob_install_lock, which serializes env mutation.
    unsafe {
        std::env::set_var("MESON_VIRUS_SCAN", "on");
    }
    clear_blob_stores_for_test();
    install_blob_store(Arc::new(LocalDiskBlobStore::new(temp_root("a")))).unwrap();
    install_quarantine_store(Arc::new(LocalDiskBlobStore::new(temp_root("q")))).unwrap();
    install_virus_scanner(scanner);

    let (system, router, default_key) = setup_valence_with_router().await;
    // Force-link the task into Boson's inventory for this test binary.
    let _ = std::any::type_name::<meson::tasks::MesonVirusScanParams>();
    let mut cfg = router_config_reject_external_system(default_key);
    cfg.actor_trust = ActorTrust::Internal;
    let factory = RouterValenceFactory::arc(router, cfg);
    let (boson, worker) = Boson::builder()
        .queue_backend(Arc::new(MemQueueBackend::new()))
        .execution_context_factory(ValenceExecutionContextFactory::new(factory))
        .auto_registry()
        .without_worker()
        .build_manual()
        .expect("manual boson");
    configure(boson.clone());
    Harness {
        system,
        boson,
        worker,
    }
}

fn meta(name: &str) -> FileCreateMeta {
    FileCreateMeta {
        file_name: name.into(),
        file_extension: "txt".into(),
        mime_type: "text/plain".into(),
        uploaded_by: owner_rid(),
    }
}

fn bare(row: &E2eMesonFile) -> String {
    row.id().unwrap().id().to_string()
}

async fn drain(worker: &ManualWorker) -> usize {
    let mut ran = 0;
    while worker.try_run_next().await {
        ran += 1;
    }
    ran
}

async fn reload(system: &Valence, id: &str) -> E2eMesonFile {
    E2eMesonFile::get(id, system, valence::use_!(r"**Test:** Reload an **E2e Meson File** in `scan_kickoff` to check its scan status after the queue drains. CI and developers running the suite only."))
        .await
        .unwrap()
        .expect("file row exists")
}

async fn build_file(
    meta: FileCreateMeta,
    storage_path: String,
    size_bytes: i64,
    status: FileFileStatus,
    uploaded_at: DateTime<Utc>,
) -> Result<E2eMesonFile, FileUploadError> {
    Ok(E2eMesonFile::new(
        meta.file_name,
        meta.file_extension,
        meta.mime_type,
        size_bytes,
        storage_path,
        status,
        meta.uploaded_by,
        uploaded_at,
    )?)
}

fn reset_scan_env() {
    // SAFETY: still under blob_install_lock.
    unsafe {
        std::env::set_var("MESON_VIRUS_SCAN", "off");
    }
    clear_blob_stores_for_test();
}

#[tokio::test]
async fn create_with_bytes_enqueues_scan_and_promotes_happy() {
    let _lock = blob_install_lock().await;
    let h = harness(Arc::new(AlwaysCleanScanner)).await;

    let created = E2eMesonFile::create_with_bytes(&h.system, meta("a.txt"), b"clean-bytes")
        .await
        .expect("create");
    assert_eq!(created.file_status(), &FileFileStatus::PendingVirusScan);
    let id = bare(&created);
    let key = created.storage_path().clone();
    assert_eq!(
        h.boson.count_jobs(Some(JobStatus::Queued)).await.unwrap(),
        1
    );

    assert_eq!(drain(&h.worker).await, 1);

    let row = reload(&h.system, &id).await;
    assert_eq!(row.file_status(), &FileFileStatus::Available);
    assert_eq!(
        installed_blob_store().unwrap().get(&key).await.unwrap(),
        b"clean-bytes"
    );
    assert!(matches!(
        installed_quarantine_store().unwrap().get(&key).await,
        Err(FileStoreError::NotFound)
    ));
    let via = get_available_file_bytes(&h.system, TABLE, &id)
        .await
        .unwrap();
    assert_eq!(via, b"clean-bytes");
    assert_eq!(
        h.boson.count_jobs(Some(JobStatus::Success)).await.unwrap(),
        1
    );
    reset_scan_env();
}

#[tokio::test]
async fn create_with_put_enqueues_scan_and_promotes_happy() {
    let _lock = blob_install_lock().await;
    let h = harness(Arc::new(AlwaysCleanScanner)).await;

    let created: E2eMesonFile = create_with_put(&h.system, meta("b.txt"), b"put-bytes", build_file)
        .await
        .expect("create_with_put");
    assert_eq!(created.file_status(), &FileFileStatus::PendingVirusScan);
    let id = bare(&created);

    assert_eq!(drain(&h.worker).await, 1);

    let row = reload(&h.system, &id).await;
    assert_eq!(row.file_status(), &FileFileStatus::Available);
    let via = get_available_file_bytes(&h.system, TABLE, &id)
        .await
        .unwrap();
    assert_eq!(via, b"put-bytes");
    reset_scan_env();
}

#[tokio::test]
async fn create_with_bytes_infected_quarantines_sad() {
    let _lock = blob_install_lock().await;
    let h = harness(Arc::new(AlwaysInfectedScanner)).await;

    let created = E2eMesonFile::create_with_bytes(&h.system, meta("c.txt"), b"bad-bytes")
        .await
        .expect("create");
    let id = bare(&created);
    let key = created.storage_path().clone();

    assert_eq!(drain(&h.worker).await, 1);

    let row = reload(&h.system, &id).await;
    assert_eq!(row.file_status(), &FileFileStatus::Quarantined);
    assert!(matches!(
        installed_blob_store().unwrap().get(&key).await,
        Err(FileStoreError::NotFound)
    ));
    assert_eq!(
        installed_quarantine_store()
            .unwrap()
            .get(&key)
            .await
            .unwrap(),
        b"bad-bytes"
    );
    match get_available_file_bytes(&h.system, TABLE, &id).await {
        Err(ReadinessError::NotAvailable { status }) => {
            assert_eq!(
                status.as_deref(),
                Some(FileFileStatus::Quarantined.as_str())
            );
        }
        other => panic!("expected NotAvailable(quarantined), got {other:?}"),
    }
    reset_scan_env();
}

#[tokio::test]
async fn caller_enqueue_after_create_is_idempotent() {
    let _lock = blob_install_lock().await;
    let h = harness(Arc::new(AlwaysCleanScanner)).await;

    let created = E2eMesonFile::create_with_bytes(&h.system, meta("d.txt"), b"twice")
        .await
        .expect("create");
    let id = bare(&created);
    // Existing callers (ocr-uf-app, lepton) still enqueue after create.
    enqueue_virus_scan(TABLE, &id)
        .await
        .expect("caller enqueue");

    let ran = drain(&h.worker).await;
    assert!((1..=2).contains(&ran), "ran {ran} jobs");

    let row = reload(&h.system, &id).await;
    assert_eq!(row.file_status(), &FileFileStatus::Available);
    assert_eq!(
        h.boson.count_jobs(Some(JobStatus::Failed)).await.unwrap(),
        0
    );
    let via = get_available_file_bytes(&h.system, TABLE, &id)
        .await
        .unwrap();
    assert_eq!(via, b"twice");
    reset_scan_env();
}

#[tokio::test]
async fn scan_off_create_does_not_enqueue() {
    let _lock = blob_install_lock().await;
    let h = harness(Arc::new(AlwaysCleanScanner)).await;
    // SAFETY: under blob_install_lock.
    unsafe {
        std::env::set_var("MESON_VIRUS_SCAN", "off");
    }

    let created = E2eMesonFile::create_with_bytes(&h.system, meta("e.txt"), b"plain")
        .await
        .expect("create");
    assert_eq!(created.file_status(), &FileFileStatus::Available);
    assert_eq!(h.boson.count_jobs(None).await.unwrap(), 0);
    assert!(!h.worker.try_run_next().await);
    reset_scan_env();
}
