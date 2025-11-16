import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

LOG_DIR = "../logs"

def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def build_logger(name, filename):
    ensure_log_dir()

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    file_path = os.path.join(LOG_DIR, filename)

    handler = RotatingFileHandler(
        file_path,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# Loggers chính
encryption_logger = build_logger("encryption", "encryption.log")
decryption_logger = build_logger("decryption", "decryption.log")
key_logger = build_logger("key_management", "key_management.log")
system_logger = build_logger("system", "system.log")
error_logger = build_logger("errors", "error.log")
s3_logger = build_logger("s3_upload", "s3_upload.log")
s3_logger = build_logger("s3_upload", "s3_upload.log")
