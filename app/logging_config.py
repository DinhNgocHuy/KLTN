import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import stat

# ============================================================
# DEFINE LOG DIRECTORY (DYNAMIC, NOT HARDCODED)
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ============================================================
# INTERNAL FUNCTION: AVOID DUPLICATE HANDLERS
# ============================================================
def _remove_duplicate_handlers(logger):
    if logger.hasHandlers():
        logger.handlers.clear()

# ============================================================
# CREATE A LOGGER
# ============================================================
def build_logger(name: str, filename: str):
    """
    Create a rotating logger with both file + console output.
    - Avoids duplicate handlers
    - Ensures file permissions (600)
    - Reusable across entire project
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    _remove_duplicate_handlers(logger)

    log_file = LOG_DIR / filename

    # Rotating File Handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8"
    )

    # Log formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console Handler (Optional but useful in dev)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Set file permission for security (Linux/Mac)
    try:
        os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass  # ignore on Windows

    return logger

# ============================================================
# GLOBAL SYSTEM LOGGERS
# ============================================================
encryption_logger = build_logger("encryption", "encryption.log")
decryption_logger = build_logger("decryption", "decryption.log")
key_logger = build_logger("key_management", "key_management.log")
system_logger = build_logger("system", "system.log")
error_logger = build_logger("errors", "error.log")
s3_upload_logger = build_logger("s3_upload", "s3_upload.log")
s3_download_logger = build_logger("s3_download", "s3_download.log")

# ============================================================
# OPTIONAL: PUBLIC ACCESSOR
# ============================================================
def get_logger(name: str):
    """Get or create logger by name"""
    return logging.getLogger(name)
