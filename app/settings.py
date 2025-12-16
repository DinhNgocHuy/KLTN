import json
import boto3
import subprocess
from pathlib import Path
from functools import lru_cache
from botocore.exceptions import ClientError
from app.logging_config import system_logger, error_logger

# ============================================================
# BASE DIRECTORIES
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent

KEY_DIR = BASE_DIR / "keys"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"

KEY_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# Terraform paths
TERRAFORM_CORE = BASE_DIR / "infra/terraform/core"
FALLBACK_CONFIG = BASE_DIR / "config.json"

# ============================================================
# ENCRYPTION / DECRYPTION PARAMETERS
# ============================================================
# AES-GCM
AES_KEY_SIZE = 32                      # 256-bit
NONCE_SIZE = 12                        # 96-bit recommended for AES-GCM
TAG_SIZE = 16                          # 128-bit GCM tag
CRYPTO_CHUNK_SIZE = 1024 * 1024 * 1024 # 1GB per chunk
STREAM_BUFFER_SIZE = 1024 * 1024       # streaming size: 1MB
MAX_GCM_BYTES = 60 * 1024 * 1024 * 1024  # 60GB safe threshold

# RSA PARAMETERS
RSA_KEY_SIZE = 4096   # recommended for security
RSA_PUBLIC_EXPONENT = 65537


# ============================================================
# TERRAFORM → GET S3 BUCKET NAME
# ============================================================
@lru_cache(maxsize=1)
@lru_cache(maxsize=1)
def get_bucket_name():
    """
    Returns validated S3 bucket name.
    Priority:
        1. Terraform live output
        2. fallback config.json
    Bucket must exist in AWS.
    """
    bucket_name = None

    # --- 1. Terraform output ---
    try:
        system_logger.info("Reading S3 bucket name from Terraform output...")

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
            cfg = json.load(open(FALLBACK_CONFIG, "r"))
            bucket_name = cfg.get("bucket_name")
        except Exception as e:
            error_logger.error(f"Failed reading fallback config.json: {e}")

    if not bucket_name:
        error_logger.error("S3 bucket name not found in any source.")
        return None

    # --- 3. REALITY CHECK: AWS ---
    if not bucket_exists(bucket_name):
        error_logger.error(
            f"S3 bucket '{bucket_name}' is configured but does not exist in AWS."
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
        error_code = int(e.response["Error"]["Code"])

        if error_code == 404:
            system_logger.error(f"S3 bucket '{bucket_name}' does not exist.")
        else:
            system_logger.error(
                f"Unable to access S3 bucket '{bucket_name}': {e}"
            )
        return False
    
# ============================================================
# SELF-TEST
# ============================================================
if __name__ == "__main__":
    print("Bucket:", get_bucket_name())
    print("KEY_DIR:", KEY_DIR)
    print("DATA_DIR:", DATA_DIR)