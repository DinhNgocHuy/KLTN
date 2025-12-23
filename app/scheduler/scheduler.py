import time
import threading
import schedule

from app.core.logging_config import system_logger
from app.storage.verify_integrity import verify_all_files
from app.crypto.key_management import rotate_keys
from app.crypto.encryption import encrypt_all_in_folder
from app.storage.s3_upload import upload_folder
from app.core.settings import DATA_DIR


# ============================================================
# JOB DEFINITIONS
# ============================================================

def job_verify_integrity():
    system_logger.info("[SCHEDULER] Running integrity check...")
    verify_all_files()
    system_logger.info("[SCHEDULER] Integrity check completed.")


def job_rotate_rsa_keys():
    system_logger.info("[SCHEDULER] Running RSA key rotation...")
    rotate_keys()
    system_logger.info("[SCHEDULER] Key rotation completed.")


def job_auto_backup():
    system_logger.info("[SCHEDULER] Running automated backup...")

    original = DATA_DIR / "original"
    encrypted = DATA_DIR / "encrypted"

    encrypt_all_in_folder(original, encrypted)
    upload_folder(encrypted)

    system_logger.info("[SCHEDULER] Automated backup completed.")


# ============================================================
# SCHEDULER CONTROLLER (THREAD-SAFE)
# ============================================================

class BackupScheduler:
    def __init__(self):
        self._running = False
        self._thread = None

    def register_jobs(self):
        schedule.clear()

        schedule.every().day.at("02:00").do(job_verify_integrity)
        schedule.every(30).days.do(job_rotate_rsa_keys)
        schedule.every().day.at("03:00").do(job_auto_backup)

        system_logger.info("[SCHEDULER] Jobs registered")

    def start(self):
        if self._running:
            system_logger.warning("[SCHEDULER] Already running")
            return

        self._running = True
        self.register_jobs()

        self._thread = threading.Thread(
            target=self._run,
            daemon=True
        )
        self._thread.start()

        system_logger.info("[SCHEDULER] Scheduler started")

    def stop(self):
        self._running = False
        system_logger.info("[SCHEDULER] Scheduler stopped")

    def _run(self):
        while self._running:
            schedule.run_pending()
            time.sleep(1)
