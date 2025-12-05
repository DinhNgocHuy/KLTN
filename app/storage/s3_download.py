import os
import json
import boto3
from pathlib import Path

from app.settings import get_bucket_name, DATA_DIR
from app.logging_config import s3_download_logger, error_logger


# ============================================================
# GLOBAL
# ============================================================
BUCKET = get_bucket_name()
s3 = boto3.client("s3")

LOCAL_DIR = Path(DATA_DIR) / "downloaded_encrypted"
LOCAL_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# VERIFY ON S3 BEFORE DOWNLOAD
# ============================================================
def verify_on_s3(filename):
    """
    Verify integrity trực tiếp trên S3:
    - Load metadata/<file>.metadata.json
    - Load metadata SHA256 từ encrypted/<file>.enc (S3 metadata)
    - So sánh checksum
    """
    meta_key = f"metadata/{filename}.metadata.json"
    enc_key = f"encrypted/{filename}.enc"

    print(f"\n=== VERIFY ON S3: {filename} ===")

    # -------- Fetch metadata.json --------
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=meta_key)
        metadata = json.loads(obj["Body"].read())
    except Exception as e:
        print(f"Cannot load metadata.json: {meta_key} — {e}")
        error_logger.error(f"metadata.json missing | {meta_key} | {e}")
        return False

    expected_sha = metadata.get("ciphertext_sha256")
    if not expected_sha:
        print("Missing ciphertext_sha256 in metadata.json")
        return False

    # -------- Fetch S3 object metadata SHA256 --------
    try:
        head = s3.head_object(Bucket=BUCKET, Key=enc_key)
        remote_sha = head.get("Metadata", {}).get("sha256")
    except Exception as e:
        print(f"Cannot read S3 metadata: {enc_key} — {e}")
        return False

    if not remote_sha:
        print("Missing sha256 in S3 metadata")
        return False

    # -------- Compare --------
    print(f"metadata.json SHA256 : {expected_sha}")
    print(f"S3 metadata SHA256    : {remote_sha}")

    if expected_sha != remote_sha:
        print("✗ INTEGRITY FAIL — File on S3 is corrupted or modified.")
        error_logger.error(
            f"S3 integrity FAIL | file={filename} | expected={expected_sha} | actual={remote_sha}"
        )
        return False

    print("✓ S3 integrity OK — Safe to download.\n")
    return True


# ============================================================
# DOWNLOAD FILE
# ============================================================
def download_s3_object(key, local_path):
    """Small wrapper for downloading with logging."""
    try:
        s3.download_file(BUCKET, key, str(local_path))
        s3_download_logger.info(f"Downloaded {key}")
        print(f"✔ Downloaded {key}")
        return True
    except Exception as e:
        print(f"Download failed: {key} — {e}")
        error_logger.error(f"Download failed | {key} | {e}")
        return False


# ============================================================
# DOWNLOAD ONE FILE BUNDLE
# ============================================================
def download_file_pair(filename):
    """
    Download: .enc + .key.enc + .metadata.json
    ONLY IF VERIFY S3 INTEGRITY = OK
    """

    # ---------- Verify S3 integrity ----------
    if not verify_on_s3(filename):
        print("Aborted. Integrity check failed. Not downloading.")
        return False

    print(f"=== DOWNLOAD BUNDLE: {filename} ===")

    enc_key = f"encrypted/{filename}.enc"
    key_key = f"keys/{filename}.key.enc"
    meta_key = f"metadata/{filename}.metadata.json"

    local_enc = LOCAL_DIR / f"{filename}.enc"
    local_key = LOCAL_DIR / f"{filename}.key.enc"
    local_meta = LOCAL_DIR / f"{filename}.metadata.json"

    # ---------- Download all three required files ----------
    if not download_s3_object(enc_key, local_enc):
        return False
    if not download_s3_object(key_key, local_key):
        return False
    if not download_s3_object(meta_key, local_meta):
        return False

    print(f"✔ Completed download for {filename}\n")
    return True

# ============================================================
# DOWNLOAD ALL ENCRYPTED FILES
# ============================================================
def download_all_encrypted():
    print(f"Listing encrypted objects in S3 bucket: {BUCKET}")

    objects = s3.list_objects_v2(Bucket=BUCKET, Prefix="encrypted/")
    if "Contents" not in objects:
        print("No encrypted files found.")
        return

    basenames = [
        os.path.basename(obj["Key"]).replace(".enc", "")
        for obj in objects["Contents"]
        if obj["Key"].endswith(".enc")
    ]

    print(f"Found {len(basenames)} encrypted files.\n")

    for base in basenames:
        download_file_pair(base)

    print("✔ DONE downloading ALL encrypted data.\n")


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys

    args = sys.argv[1:]

    if "--all" in args:
        download_all_encrypted()
        exit()

    if "--file" in args:
        idx = args.index("--file")
        filename = args[idx + 1]
        download_file_pair(filename)
        exit()

    print("Usage:")
    print("  python -m app.storage.s3_download --file <filename>")
    print("  python -m app.storage.s3_download --all")