import os
import json
import boto3
import sys
import logging
from pathlib import Path

from app.core.settings import get_bucket_name, DATA_DIR
from app.utils.checksum import sha256_file

# ============================================================
# LOGGING
# ============================================================

LOG_DIR = Path(DATA_DIR).parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

verify_logger = logging.getLogger("verify_integrity")
verify_logger.setLevel(logging.INFO)

if not verify_logger.handlers:
    fh = logging.FileHandler(LOG_DIR / "verify_integrity.log")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    verify_logger.addHandler(fh)

verify_error_logger = logging.getLogger("verify_integrity_error")
verify_error_logger.setLevel(logging.ERROR)

if not verify_error_logger.handlers:
    efh = logging.FileHandler(LOG_DIR / "verify_integrity_error.log")
    efh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    verify_error_logger.addHandler(efh)


# ============================================================
# CORE VERIFY LOGIC
# ============================================================

def verify_local(enc_file_path: str) -> bool:
    """
    Verify local .enc file using its metadata.json
    """
    base = enc_file_path.replace(".enc", "")
    metadata_path = f"{base}.metadata.json"

    if not os.path.exists(metadata_path):
        verify_error_logger.error(f"Missing metadata: {metadata_path}")
        return False

    metadata = json.loads(open(metadata_path, "r").read())

    expected_sha = metadata.get("ciphertext_sha256")
    if not expected_sha:
        verify_error_logger.error(f"Missing ciphertext_sha256 in {metadata_path}")
        return False

    actual_sha = sha256_file(enc_file_path)

    if actual_sha != expected_sha:
        verify_error_logger.error(
            f"Local verify FAIL | file={enc_file_path} | expected={expected_sha} | actual={actual_sha}"
        )
        return False

    verify_logger.info(f"Local verify OK | file={enc_file_path}")
    return True


def verify_on_s3(filename: str) -> bool:
    """
    Verify integrity of encrypted file on S3 without downloading it
    """
    BUCKET = get_bucket_name()
    s3 = boto3.client("s3")

    meta_key = f"metadata/{filename}.metadata.json"
    enc_key = f"encrypted/{filename}.enc"

    try:
        obj = s3.get_object(Bucket=BUCKET, Key=meta_key)
        metadata = json.loads(obj["Body"].read())
    except Exception as e:
        verify_error_logger.error(f"Cannot fetch metadata.json: {e}")
        return False

    expected_sha = metadata.get("ciphertext_sha256")
    if not expected_sha:
        verify_error_logger.error("metadata.json missing ciphertext_sha256")
        return False

    try:
        head = s3.head_object(Bucket=BUCKET, Key=enc_key)
        remote_sha = head.get("Metadata", {}).get("sha256")
    except Exception as e:
        verify_error_logger.error(f"Cannot read S3 metadata: {e}")
        return False

    if not remote_sha:
        verify_error_logger.error("S3 object metadata missing sha256")
        return False

    if expected_sha != remote_sha:
        verify_error_logger.error(
            f"S3 verify FAIL | file={filename}.enc | expected={expected_sha} | actual={remote_sha}"
        )
        return False

    verify_logger.info(f"S3 verify OK | file={filename}.enc")
    return True


# ============================================================
# UNIFIED API (USED BY GUI & SCHEDULER)
# ============================================================

def verify_integrity(filename: str) -> bool:
    """
    GUI/Scheduler entrypoint.
    Verify encrypted file in local encrypted folder by filename.
    """
    enc_path = Path(DATA_DIR) / "encrypted" / f"{filename}.enc"
    return verify_local(str(enc_path))


def verify_all_files():
    """
    Scheduler entrypoint.
    Verify all encrypted files in local encrypted folder.
    """
    encrypted_dir = Path(DATA_DIR) / "encrypted"

    for enc_file in encrypted_dir.glob("*.enc"):
        verify_local(str(enc_file))


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    args = sys.argv

    if len(args) < 3:
        print("Usage:")
        print("  python -m app.storage.verify_integrity --local <path/to/file.enc>")
        print("  python -m app.storage.verify_integrity --s3 <filename_without_ext>")
        sys.exit(1)

    mode = args[1]

    if mode == "--local":
        verify_local(args[2])

    elif mode == "--s3":
        verify_on_s3(args[2])

    else:
        print("Invalid option. Use --local or --s3")
