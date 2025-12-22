import os
import json
import hashlib
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
os.makedirs(LOG_DIR, exist_ok=True)

verify_logger = logging.getLogger("verify_integrity")
verify_logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_DIR / "verify_integrity.log")
fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
verify_logger.addHandler(fh)

verify_error_logger = logging.getLogger("verify_integrity_error")
verify_error_logger.setLevel(logging.ERROR)
efh = logging.FileHandler(LOG_DIR / "verify_integrity_error.log")
efh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
verify_error_logger.addHandler(efh)


# ============================================================
# VERIFY LOCAL (after download)
# ============================================================
def verify_local(enc_file_path):
    """Verify .enc file integrity using metadata.json (local)."""

    base = enc_file_path.replace(".enc", "")
    metadata_path = f"{base}.metadata.json"

    if not os.path.exists(metadata_path):
        print(f"Metadata not found: {metadata_path}")
        verify_error_logger.error(f"Missing metadata: {metadata_path}")
        return False

    metadata = json.loads(open(metadata_path, "r").read())

    required = ["ciphertext_sha256", "nonce", "tag"]
    for k in required:
        if k not in metadata:
            print(f"Missing field `{k}` in metadata.")
            verify_error_logger.error(f"Missing `{k}` in {metadata_path}")
            return False

    expected_sha = metadata["ciphertext_sha256"]
    actual_sha = sha256_file(enc_file_path)

    print(f"Expected SHA256: {expected_sha}")
    print(f"Actual   SHA256: {actual_sha}")

    if actual_sha != expected_sha:
        print("Local integrity FAILED.")
        verify_error_logger.error(
            f"Local verify FAIL | file={enc_file_path} | expected={expected_sha} | actual={actual_sha}"
        )
        return False

    print("Local integrity OK.")
    verify_logger.info(f"Local verify OK | file={enc_file_path}")
    return True

# ============================================================
# VERIFY ON S3 (without downloading .enc)
# ============================================================
def verify_on_s3(filename):
    """
    Verify integrity on S3:
    - Load metadata/{filename}.metadata.json
    - Load S3 metadata from encrypted/{filename}.enc
    - Compare SHA256
    """

    BUCKET = get_bucket_name()
    s3 = boto3.client("s3")

    meta_key = f"metadata/{filename}.metadata.json"
    enc_key = f"encrypted/{filename}.enc"

    print(f"\n=== VERIFY ON S3: {filename} ===")

    # 1) Fetch metadata.json from S3
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=meta_key)
        metadata = json.loads(obj["Body"].read())
    except Exception as e:
        print(f"Cannot fetch metadata.json: {meta_key} — {e}")
        return False

    expected_sha = metadata.get("ciphertext_sha256")
    if not expected_sha:
        print("metadata.json missing field: ciphertext_sha256")
        return False

    # 2) Fetch SHA256 from S3 object metadata
    try:
        head = s3.head_object(Bucket=BUCKET, Key=enc_key)
        remote_sha = head.get("Metadata", {}).get("sha256")
    except Exception as e:
        print(f"Cannot read S3 metadata: {enc_key} — {e}")
        return False

    if not remote_sha:
        print("S3 metadata missing sha256")
        return False

    print(f"Metadata.json SHA256 : {expected_sha}")
    print(f"S3 object SHA256     : {remote_sha}")

    # 3) Compare
    if expected_sha != remote_sha:
        print("✗ INTEGRITY FAIL — File on S3 is corrupted or modified.")
        verify_error_logger.error(
            f"S3 integrity FAIL | file={filename}.enc | expected={expected_sha} | actual={remote_sha}"
        )
        return False

    print("✓ S3 integrity OK — File is valid.")
    verify_logger.info(f"S3 verify OK | file={filename}.enc")
    return True


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
        enc_path = args[2]
        verify_local(enc_path)

    elif mode == "--s3":
        filename = args[2]
        verify_on_s3(filename)

    else:
        print("Invalid option. Use --local or --s3")
