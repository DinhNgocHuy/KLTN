import time
import schedule
from datetime import datetime

from app.logging_config import system_logger
from app.storage.verify_integrity import verify_all_files
from app.crypto.key_management import rotate_keys
from app.crypto.encryption import encrypt_all_in_folder
from app.storage.s3_upload import upload_folder
from app.settings import DATA_DIR


# ============================================================
# 1) Integrity Check Job
# ============================================================
def job_verify_integrity():
    system_logger.info("[SCHEDULER] Running integrity check...")
    verify_all_files()
    system_logger.info("[SCHEDULER] Integrity check completed.")


# ============================================================
# 2) Key Rotation Job
# ============================================================
def job_rotate_rsa_keys():
    system_logger.info("[SCHEDULER] Running RSA key rotation...")
    rotate_keys()
    system_logger.info("[SCHEDULER] Key rotation completed.")


# ============================================================
# 3) Auto Backup Job
# ============================================================
def job_auto_backup():
    system_logger.info("[SCHEDULER] Running automated backup...")

    original = DATA_DIR / "original"
    encrypted = DATA_DIR / "encrypted"

    encrypt_all_in_folder(original, encrypted)
    upload_folder(encrypted)

    system_logger.info("[SCHEDULER] Automated backup completed.")


# ============================================================
# 4) Register Scheduled Tasks
# ============================================================
def start_scheduler():
    system_logger.info("[SCHEDULER] Starting task scheduler...")

    # Run daily integrity check at 02:00
    schedule.every().day.at("02:00").do(job_verify_integrity)

    # Rotate keys every 30 days
    schedule.every(30).days.do(job_rotate_rsa_keys)

    # Automated backup every night at 03:00
    schedule.every().day.at("03:00").do(job_auto_backup)

    # Main loop
    while True:
        schedule.run_pending()
        time.sleep(1)
