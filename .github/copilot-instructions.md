# Copilot / AI agent instructions for this repo

Summary: concise guidance to help an AI coding agent be productive in this Backup & Encryption project.

- **Big picture**: This is a local backup + encryption tool that encrypts files with AES-GCM, wraps AES keys with RSA, and stores artifacts in S3. Core components live under `app/`:
  - **`app/crypto`**: AES-GCM encryption, chunked mode for >60GB, RSA envelope keys and key rotation.
  - **`app/storage`**: S3 upload/download and metadata handling.
  - **`app/watcher`**: filesystem watcher that triggers encrypt→upload on new files.
  - **`app/scheduler`**: scheduled jobs (integrity checks, RSA rotation, auto backup).
  - **`app/core`**: logging, settings, config management (paths, runtime behavior).

- **Runtime modes & important paths**:
  - In development run from repo root; paths use `app/core/settings.py` (`APP_DIR`, `BASE_DIR`, `DATA_DIR`, `KEY_DIR`, `LOG_DIR`).
  - When packaged with PyInstaller `is_frozen()` switches directories to `%USERPROFILE%/.encrypted_backup`.
  - Data layout examples: `data/original`, `data/encrypted`, `data/decrypted`, `data/downloaded`.

- **S3 bucket resolution** (important example): see `app/core/settings.py`
  - Priority: runtime override via `set_bucket_name()`, then `terraform output` (infra/terraform/core), then `config.json` fallback.
  - Agents should prefer the runtime override when testing locally (the GUI calls `set_bucket_name`).

- **Key management & formats**:
  - RSA keys are versioned (folders like `app/keys/rsa/v1`, `v2`, … and `current`).
  - AES envelope: AES key is written to `<filename>.key.enc`, metadata in `<filename>.enc.metadata.json` with `key_version`, `nonce`, `tag`.
  - Rotation re-wraps AES keys and updates metadata; see `app/crypto/key_management.py` for the rotate flow.

- **Encryption modes & thresholds**:
  - Single-file AES-GCM is used for files <= `MAX_GCM_BYTES` (see `app/core/settings.py`).
  - Chunked AES-GCM mode produces a `.chunks/` directory and header.json for very large files; implementation in `app/crypto/encryption.py`.

- **Logging & observability**:
  - Persistent logs are created under `logs/` and configured by `app/core/logging_config.py`.
  - Logger names to reference in code: `system`, `error`, `crypto.encryption`, `storage.s3_upload`, etc.

- **Developer workflows & useful commands**:
  - Run GUI (dev): `python main.py` — GUI entrypoint is [main.py](main.py).
  - Run background watcher agent: `python agent.py` — uses `app/watcher/folder_watcher.py`.
  - Build standalone exe: there is `build.bat` and `build/` artifacts (project uses PyInstaller; inspect `build.bat` and `backup_app.spec`).
  - Terraform infra: see [infra/terraform/core](infra/terraform/core) — `app/core/settings.get_bucket_name()` expects `terraform output -json` to expose bucket id.

- **Project-specific conventions & patterns** (to follow when editing):
  - Explicit file-based metadata next to ciphertext files (`*.enc.metadata.json`) — preserve metadata schema when changing encryption code.
  - Key versions are authoritative: update `current`/version using functions in `app/crypto/rsa_utils.py` and `key_management.py` (avoid ad-hoc changes to key files).
  - Avoid importing `app/core/logging_config` into `app/core/settings` (the code intentionally uses logger placeholders in settings to avoid circular imports).
  - Long-running tasks (encrypt+upload) run in background threads; maintain thread-safety when modifying shared state.

- **Integration points / external deps**:
  - AWS via `boto3` (S3 head/create/upload). Environment variables used by GUI: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_S3_BUCKET`.
  - `cryptography` for AES/RSA primitives.
  - `watchdog` for filesystem events and `schedule` for cron-like jobs.

- **Files to inspect for concrete examples**:
  - [app/core/settings.py](app/core/settings.py) — runtime paths, bucket resolution, constants.
  - [app/crypto/encryption.py](app/crypto/encryption.py) — AES-GCM single vs chunked, metadata format.
  - [app/crypto/key_management.py](app/crypto/key_management.py) — rotation sequence and S3 key uploading.
  - [app/watcher/folder_watcher.py](app/watcher/folder_watcher.py) — stable-file checks and processing lifecycle.
  - [gui/backup_app.py](gui/backup_app.py) — runtime overrides, GUI flows and examples of `set_bucket_name` and RSA init/rotate.

- **When making changes, prefer these verification steps**:
  - Run unit/manual smoke: encrypt a small file into `data/encrypted`, inspect `<file>.enc` and `<file>.key.enc` and the metadata JSON.
  - Confirm logs appear under `logs/` (system/crypto/storage) and check logger names.
  - If changing bucket resolution, verify `terraform output -json` usage or GUI `set_bucket_name()` path.

If anything here is unclear or you want more detail about any area (packaging, terraform integration, or key rotation), tell me which part to expand or update.
