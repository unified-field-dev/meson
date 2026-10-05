//! Start the virus scan for a File row that was just created as Pending.
//!
//! [`crate::FileUpload::create_with_bytes`] and [`crate::create_with_put`] call
//! [`kick_off`] after a `PendingVirusScan` create so callers do not have to
//! remember [`enqueue_virus_scan`](crate::enqueue::enqueue_virus_scan). A caller
//! that still enqueues is harmless: both share the LWT key
//! `virus_scan:{table}:{id}`, and the task skips rows that are already terminal.

use valence::RecordId;

/// Enqueue `meson_virus_scan` for a freshly created Pending row.
///
/// Best-effort: failures are logged and the row stays `PendingVirusScan`, so the
/// file is never served. A later `enqueue_virus_scan` call or the
/// `meson_virus_scan_sweeper` script can start the scan again.
pub(crate) async fn kick_off(operation: &'static str, table: &str, id: Option<&RecordId>) {
    let Some(rid) = id else {
        tracing::warn!(
            target: "meson.file_upload",
            operation,
            table,
            outcome = "scan_enqueue_failed",
            reason_class = "missing_id",
            "created File row has no id; scan not enqueued"
        );
        return;
    };
    enqueue(operation, table, rid.id()).await;
}

#[cfg(feature = "scan-boson")]
async fn enqueue(operation: &'static str, table: &str, file_id: &str) {
    use crate::enqueue::{enqueue_virus_scan, EnqueueScanError};

    if crate::file_scan_adapter::file_scan_adapter(table).is_err() {
        // The task could never load the row; skip instead of queueing a doomed job.
        tracing::warn!(
            target: "meson.file_upload",
            operation,
            table,
            file_id,
            outcome = "no_scan_adapter",
            "no FileScanAdapter registered for table; scan not enqueued"
        );
        return;
    }
    match enqueue_virus_scan(table, file_id).await {
        Ok(_) => tracing::info!(
            target: "meson.file_upload",
            operation,
            table,
            file_id,
            outcome = "scan_enqueued",
            "virus scan enqueued for pending file"
        ),
        Err(err) => {
            let reason_class = match err {
                EnqueueScanError::BosonNotConfigured => "boson_not_configured",
                EnqueueScanError::Enqueue => "enqueue_failed",
            };
            tracing::warn!(
                target: "meson.file_upload",
                operation,
                table,
                file_id,
                outcome = "scan_enqueue_failed",
                reason_class,
                "virus scan not enqueued; file stays pending"
            );
        }
    }
}

#[cfg(not(feature = "scan-boson"))]
async fn enqueue(operation: &'static str, table: &str, file_id: &str) {
    tracing::debug!(
        target: "meson.file_upload",
        operation,
        table,
        file_id,
        outcome = "scan_boson_disabled",
        "scan-boson feature off; caller or sweeper must enqueue the scan"
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::kick_off;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    async fn logs_of<F: std::future::Future<Output = ()>>(fut: F) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        fut.await;
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn missing_id_logs_and_skips_sad() {
        let logs = logs_of(kick_off("create_with_put", "e2e_meson_file", None)).await;
        assert!(logs.contains("missing_id"), "logs: {logs}");
        assert!(!logs.contains("scan_enqueued"), "logs: {logs}");
    }

    #[cfg(feature = "scan-boson")]
    #[tokio::test]
    async fn unregistered_table_skips_enqueue_sad() {
        let rid = valence::RecordId::new("no_adapter_table", "f1");
        let logs = logs_of(kick_off(
            "create_with_bytes",
            "no_adapter_table",
            Some(&rid),
        ))
        .await;
        assert!(logs.contains("no_scan_adapter"), "logs: {logs}");
        assert!(!logs.contains("boson_not_configured"), "logs: {logs}");
        assert!(!logs.contains("scan_enqueued"), "logs: {logs}");
    }
}
