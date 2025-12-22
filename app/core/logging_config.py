import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ============================================================
# BASE DIRECTORIES
# ============================================================
APP_DIR  = Path(__file__).resolve().parent.parent   # F:\KLTN\app
BASE_DIR = APP_DIR.parent                           # F:\KLTN
LOG_DIR  = BASE_DIR / "logs"

SYSTEM_DIR  = LOG_DIR / "system"
ERROR_DIR   = LOG_DIR / "error"
CRYPTO_DIR  = LOG_DIR / "crypto"
STORAGE_DIR = LOG_DIR / "storage"

for d in [SYSTEM_DIR, ERROR_DIR, CRYPTO_DIR, STORAGE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ============================================================
# FORMATTER
# ============================================================
FORMATTER = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)

# ============================================================
# INTERNAL HELPER
# ============================================================
def _build_logger(name: str, log_file: Path, level: int):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        return logger

    handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    handler.setFormatter(FORMATTER)
    logger.addHandler(handler)
    logger.propagate = False
    return logger

# ============================================================
# SYSTEM / ERROR
# ============================================================
system_logger = _build_logger(
    "system",
    SYSTEM_DIR / "system.log",
    logging.INFO
)

error_logger = _build_logger(
    "error",
    ERROR_DIR / "error.log",
    logging.ERROR
)

# ============================================================
# CRYPTO
# ============================================================
encryption_logger = _build_logger(
    "crypto.encryption",
    CRYPTO_DIR / "encryption.log",
    logging.INFO
)

decryption_logger = _build_logger(
    "crypto.decryption",
    CRYPTO_DIR / "decryption.log",
    logging.INFO
)

key_logger = _build_logger(
    "crypto.key",
    CRYPTO_DIR / "key_management.log",
    logging.INFO
)

# ============================================================
# STORAGE
# ============================================================
storage_logger = _build_logger(
    "storage",
    STORAGE_DIR / "storage.log",
    logging.INFO
)

s3_upload_logger = _build_logger(
    "storage.s3_upload",
    STORAGE_DIR / "s3_upload.log",
    logging.INFO
)

s3_download_logger = _build_logger(
    "storage.s3_download",
    STORAGE_DIR / "s3_download.log",
    logging.INFO
)
