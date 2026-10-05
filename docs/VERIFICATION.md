# Meson verification

Re-run after code or doc changes. Covered by unit + integration tests below.

## Environment

```bash
export CARGO_BUILD_JOBS=1
```

## Gates (local backend)

From the repository root:

```bash
cargo fmt --all -- --check
cargo clippy -p meson --all-targets --features backend-local -- -D warnings
cargo test -p meson --features backend-local
cargo test -p meson --features "backend-local,scanner-clamav" --lib
cargo test -p meson --features "backend-local,scan-pipeline" --test virus_scan_pipeline
cargo test -p meson --features "backend-local,scan-pipeline" --test scan_kickoff --test scan_kickoff_no_boson
cargo test -p meson --features "backend-local,scan-pipeline" --lib scan_kickoff
cargo clippy -p meson --all-targets --features backend-local,scan-pipeline -- -D warnings
cargo test -p meson-leptos --lib
cargo run -p meson --example upload_and_load
cargo doc -p meson --no-deps --features backend-local,backend-rustfs,scan-pipeline
```

## Gates (RustFS backend)

Start RustFS (`docker.io/rustfs/rustfs:latest`), then set **local lab only**
credentials (not production secrets):

```bash
export MESON_RUSTFS_ENDPOINT=http://127.0.0.1:9000
export MESON_RUSTFS_BUCKET=meson-ci
export MESON_RUSTFS_ACCESS_KEY=mesonlabaccess
export MESON_RUSTFS_SECRET_KEY=mesonlabsecret
export MESON_RUSTFS_REQUIRED=1
cargo clippy -p meson --all-targets --features backend-local,backend-rustfs -- -D warnings
cargo test -p meson --features backend-local,backend-rustfs -- --test-threads=1
```

CI runs both `quality-local` and `quality-rustfs` (service container).

## Crate test coverage

- Backend unit tests cover LocalDisk put/get/delete and InvalidKey path escape
  (including empty, absolute, and backslash keys).
- Preview classifier unit tests cover image / text / unsupported mime classes.
- File IO helpers (`tests/file_io_helpers.rs`): `create_with_bytes` +
  `get_file_bytes` happy; missing install; missing blob; Valence deny after put;
  owner-scoped FileQueryAll IDOR.
- Integration tests (`tests/file_query_all_ownership.rs`) cover FileQueryAll list
  happy, IDOR / owned-row selection sad, preview image happy, preview forbidden sad,
  and ProfilePhoto-as-File FileQueryAll happy.
- Example: `cargo run -p meson --example upload_and_load` →
  `ok uploaded+loaded 5 bytes`.
- RustFS scenarios (`tests/rustfs_backend.rs`): put/get/delete happy, not-found sad,
  auth sad, InvalidKey without network (`MESON_RUSTFS_REQUIRED=1` in CI).
- Host env: `MESON_BLOB_BACKEND=local|rustfs` via `blob_store_from_env` +
  `install_blob_store`.

## Monorepo / UF hosts

These steps assume a Unified Field workspace checkout (paths under
`~/unified-field`). Skip them when working from a standalone meson clone.

### Host e2e scenarios

Embedded Playwright: `meson-my-files-list-happy` +
`meson-my-files-anonymous-gate-sad` (peer IDOR remains L1
`meson-my-files-idor-sad`).
