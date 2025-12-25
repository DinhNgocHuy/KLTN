import json
import boto3
import subprocess
import logging
import sys
from pathlib import Path
from functools import lru_cache
from botocore.exceptions import ClientError

# ============================================================
# RUNTIME MODE
# ============================================================

def is_frozen() -> bool:
    """
    True when running as PyInstaller-built executable.
    """
    return getattr(sys, "frozen", False)


# ============================================================
# BASE DIRECTORIES (DEV vs BUILT APP)
# ============================================================

if is_frozen():
    # ===== BUILT APP (.exe) =====
    APP_HOME = Path.home() / ".encrypted_backup"

    APP_DIR  = APP_HOME / "app"     # logical only, không cần tồn tại
    BASE_DIR = APP_HOME

    KEY_DIR  = APP_HOME / "keys"
    DATA_DIR = APP_HOME / "data"
    LOG_DIR  = APP_HOME / "logs"

else:
    # ===== DEV MODE =====
    APP_DIR  = Path(__file__).resolve().parent.parent   # F:\KLTN\app
    BASE_DIR = APP_DIR.parent                           # F:\KLTN

    KEY_DIR  = APP_DIR / "keys"                         # F:\KLTN\app\keys
    DATA_DIR = BASE_DIR / "data"                        # F:\KLTN\data
    LOG_DIR  = BASE_DIR / "logs"                        # F:\KLTN\logs


# ============================================================
# INIT REQUIRED DIRECTORIES
# ============================================================

KEY_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# subfolders used by existing code (tạo sẵn cho an toàn)
(DATA_DIR / "encrypted").mkdir(exist_ok=True)
(DATA_DIR / "decrypted").mkdir(exist_ok=True)
(DATA_DIR / "downloaded").mkdir(exist_ok=True)

(LOG_DIR / "system").mkdir(exist_ok=True)
(LOG_DIR / "crypto").mkdir(exist_ok=True)
(LOG_DIR / "storage").mkdir(exist_ok=True)


# ============================================================
# LOGGER PLACEHOLDERS
# (KHÔNG import logging_config để tránh circular import)
# ============================================================

system_logger = logging.getLogger("system")
error_logger  = logging.getLogger("error")


# ============================================================
# ENCRYPTION / DECRYPTION PARAMETERS
# ============================================================

# AES-GCM
AES_KEY_SIZE = 32        # 256-bit
NONCE_SIZE   = 12        # 96-bit
TAG_SIZE     = 16        # 128-bit

# streaming / chunking
CRYPTO_CHUNK_SIZE   = 1024 * 1024 * 1024   # 1GB
STREAM_BUFFER_SIZE  = 1024 * 1024          # 1MB
MAX_GCM_BYTES       = 60 * 1024 * 1024 * 1024  # 60GB safe threshold

# RSA
RSA_KEY_SIZE        = 4096
RSA_PUBLIC_EXPONENT = 65537


# ============================================================
# TERRAFORM / CONFIG PATHS
# ============================================================

TERRAFORM_CORE  = BASE_DIR / "infra/terraform/core"
FALLBACK_CONFIG = BASE_DIR / "config.json"


# ============================================================
# TERRAFORM → GET S3 BUCKET NAME
# ============================================================
# ============================================================
# RUNTIME OVERRIDE (GUI)
# ============================================================

_RUNTIME_BUCKET_NAME = None

def set_bucket_name(name: str):
    """
    Override S3 bucket name at runtime (used by GUI).
    """
    global _RUNTIME_BUCKET_NAME
    _RUNTIME_BUCKET_NAME = name

    # clear cached get_bucket_name()
    try:
        get_bucket_name.cache_clear()
    except Exception:
        pass
# ============================================================


@lru_cache(maxsize=1)
def get_bucket_name():
    """
    Returns validated S3 bucket name.
    Priority:
        1. Terraform live output
        2. fallback config.json
    Bucket must exist in AWS.
    """
    global _RUNTIME_BUCKET_NAME

    # 0. GUI runtime override
    if _RUNTIME_BUCKET_NAME:
        return _RUNTIME_BUCKET_NAME
    
    bucket_name = None

    # --- 1. Terraform output ---
    try:
        system_logger.info("Reading S3 bucket name from Terraform output")

        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=str(TERRAFORM_CORE),
            capture_output=True,
            text=True,
            timeout=10,
            check=True
        )

        outputs = json.loads(result.stdout)
        bucket_name = outputs.get("id", {}).get("value")

    except Exception as e:
        error_logger.error(f"Terraform output error: {e}")

    # --- 2. Fallback config ---
    if not bucket_name and FALLBACK_CONFIG.exists():
        system_logger.warning("Using fallback config.json")
        try:
            with open(FALLBACK_CONFIG, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            bucket_name = cfg.get("bucket_name")
        except Exception as e:
            error_logger.error(f"Failed reading fallback config.json: {e}")

    if not bucket_name:
        error_logger.error("S3 bucket name not found in any source")
        return None

    # --- 3. Reality check: AWS ---
    if not bucket_exists(bucket_name):
        error_logger.error(
            f"S3 bucket '{bucket_name}' is configured but does not exist"
        )
        return None

    system_logger.info(f"S3 bucket validated: {bucket_name}")
    return bucket_name


def bucket_exists(bucket_name: str) -> bool:
    """
    Check S3 bucket existence using AWS API (HeadBucket).
    """
    s3 = boto3.client("s3")

    try:
        s3.head_bucket(Bucket=bucket_name)
        return True

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")

        if code == "404":
            error_logger.error(f"S3 bucket '{bucket_name}' does not exist")
        else:
            error_logger.error(f"Unable to access S3 bucket '{bucket_name}': {e}")

        return False


# ============================================================
# SELF-TEST
# ============================================================

if __name__ == "__main__":
    print("Frozen   :", is_frozen())
    print("APP_DIR  :", APP_DIR)
    print("BASE_DIR :", BASE_DIR)
    print("KEY_DIR  :", KEY_DIR)
    print("DATA_DIR :", DATA_DIR)
    print("LOG_DIR  :", LOG_DIR)
    print("Bucket   :", get_bucket_name())
