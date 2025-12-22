from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
from pathlib import Path
import threading

from app.core.config_manager import load_config
from app.crypto.encryption import encrypt_file
from app.storage.s3_upload import upload_all_encrypted
from app.core.settings import DATA_DIR
from app.core.logging_config import system_logger


# ===============================
# CONSTANTS
# ===============================
IGNORE_EXTENSIONS = (".tmp", ".part", ".download", ".enc", ".key.enc", ".json")
FILE_STABLE_CHECK_INTERVAL = 1      # seconds
FILE_STABLE_MAX_RETRY = 15           # seconds


class FolderWatcherHandler(FileSystemEventHandler):
    """
    Handle filesystem events for auto-backup.
    Trigger encryption + upload when a new valid file is created.
    """

    def __init__(self, password: str, logger):
        self.password = password
        self.logger = logger
        self._processing = set()  # prevent duplicate processing

    def on_created(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        # -------------------------------
        # BASIC SAFETY CHECKS
        # -------------------------------
        if not file_path.exists():
            return

        if file_path.suffix.lower() in IGNORE_EXTENSIONS:
            self.logger.info(f"[WATCHER] Ignored temporary file: {file_path.name}")
            return

        # Prevent encrypting internal data directory
        if DATA_DIR in file_path.parents:
            self.logger.warning(
                f"[WATCHER] Ignored internal data file: {file_path}"
            )
            return

        # Prevent duplicate triggers
        if file_path in self._processing:
            return

        self._processing.add(file_path)

        self.logger.info(f"[WATCHER] New file detected: {file_path}")

        # Run heavy job in background thread
        threading.Thread(
            target=self._process_file,
            args=(file_path,),
            daemon=True
        ).start()

    def _process_file(self, file_path: Path):
        try:
            self._wait_until_complete(file_path)

            enc_dir = Path(DATA_DIR) / "encrypted"
            enc_dir.mkdir(parents=True, exist_ok=True)

            enc_path = enc_dir / f"{file_path.name}.enc"
            key_path = enc_dir / f"{file_path.name}.key.enc"

            encrypt_file(
                input_path=str(file_path),
                output_path=str(enc_path),
                key_output_path=str(key_path),
                password=self.password
            )

            upload_all_encrypted(str(enc_path), str(key_path))

            self.logger.info(f"✓ Auto-backed up successfully: {file_path.name}")

        except Exception as exc:
            self.logger.error(
                f"[WATCHER] Failed to process {file_path.name}: {exc}",
                exc_info=True
            )
        finally:
            self._processing.discard(file_path)

    def _wait_until_complete(self, path: Path):
        """
        Wait until file size is stable to avoid encrypting
        a partially written file.
        """
        last_size = -1

        for _ in range(FILE_STABLE_MAX_RETRY):
            try:
                current_size = path.stat().st_size
            except FileNotFoundError:
                raise RuntimeError("File disappeared before processing")

            if current_size == last_size:
                return

            last_size = current_size
            time.sleep(FILE_STABLE_CHECK_INTERVAL)

        raise RuntimeError("File write not completed (timeout)")


def start_folder_watcher():
    """
    Start auto-backup folder watcher based on config.
    Returns Observer instance if started, otherwise None.
    """
    config = load_config()

    auto_cfg = config.get("auto_backup", {})
    if not auto_cfg.get("enabled", False):
        system_logger.info("Auto backup is disabled in config.")
        return None

    watch_folder = auto_cfg.get("watch_folder")
    password = auto_cfg.get("rsa_password")

    if not watch_folder:
        system_logger.warning(
            "Auto backup enabled but watch_folder is not configured."
        )
        return None

    watch_path = Path(watch_folder)
    if not watch_path.exists() or not watch_path.is_dir():
        system_logger.error(
            f"Watch folder does not exist or is not a directory: {watch_folder}"
        )
        return None

    handler = FolderWatcherHandler(password=password, logger=system_logger)
    observer = Observer()
    observer.schedule(handler, str(watch_path), recursive=False)
    observer.start()

    system_logger.info(f"Auto backup watcher started for folder: {watch_folder}")
    return observer