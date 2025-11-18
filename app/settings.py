import json
import subprocess
from pathlib import Path
from functools import lru_cache
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
AES_KEY_SIZE = 32         # 256-bit
NONCE_SIZE = 12           # 96-bit recommended for AES-GCM
TAG_SIZE = 16             # 128-bit GCM tag
CHUNK_SIZE = 1024 * 1024  # streaming size: 1MB

# RSA PARAMETERS
RSA_KEY_SIZE = 4096   # recommended for security
RSA_PUBLIC_EXPONENT = 65537

# ============================================================
# TERRAFORM → GET S3 BUCKET NAME
# ============================================================
@lru_cache(maxsize=1)
def get_bucket_name():
    """
    Returns S3 bucket name from Terraform.
    Priority:
        1. Terraform live output
        2. fallback config.json (offline mode)
    """
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
        bucket_name = outputs.get("id", {}).get("value", None)

        if bucket_name:
            system_logger.info(f"S3 Bucket (Terraform): {bucket_name}")
            return bucket_name

        system_logger.warning("Terraform output missing id.value")

    except subprocess.CalledProcessError as e:
        error_logger.error("Terraform error. Did you run `terraform apply`?")
        error_logger.error(str(e))

    except FileNotFoundError:
        error_logger.error("Terraform binary not found.")

    except Exception as e:
        error_logger.error(f"Unexpected error reading Terraform output: {e}")

    # Fallback mode
    if FALLBACK_CONFIG.exists():
        system_logger.warning("Using fallback config.json")

        try:
            cfg = json.load(open(FALLBACK_CONFIG, "r"))
            b = cfg.get("bucket_name", None)
            if b:
                system_logger.info(f"S3 Bucket (fallback): {b}")
                return b

        except Exception as e:
            error_logger.error(f"Failed reading fallback config.json: {e}")

    error_logger.error("S3 Bucket not found!")
    return None

# ============================================================
# SELF-TEST
# ============================================================
if __name__ == "__main__":
    print("Bucket:", get_bucket_name())
    print("KEY_DIR:", KEY_DIR)
    print("DATA_DIR:", DATA_DIR)