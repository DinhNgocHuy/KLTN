import os
import json
import boto3
from pathlib import Path

from app.core.settings import get_bucket_name, DATA_DIR
from app.core.logging_config import s3_download_logger, error_logger


# ============================================================
# HELPER: Get bucket name safely
# ============================================================
def _get_bucket():
    """Get bucket name and validate"""
    bucket = get_bucket_name()
    if not bucket:
        error_logger.error("S3 bucket name not configured")
        raise ValueError("S3 bucket name not configured. Please set it in Settings.")
    return bucket


# ============================================================
# S3 CLIENT
# ============================================================
def _get_s3_client():
    """Get configured S3 client"""
    return boto3.client("s3")


# ============================================================
# LOCAL DIRECTORY
# ============================================================
LOCAL_DIR = Path(DATA_DIR) / "downloaded"
LOCAL_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# VERIFY ON S3 BEFORE DOWNLOAD
# ============================================================
def verify_on_s3(filename):
    """
    Verify integrity directly on S3:
    - Load metadata/<file>.metadata.json
    - Load metadata SHA256 from encrypted/<file>.enc (S3 metadata)
    - Compare checksum
    
    Returns:
        True if integrity check passed, False otherwise
    """
    bucket = _get_bucket()
    s3 = _get_s3_client()
    
    meta_key = f"metadata/{filename}.metadata.json"
    enc_key = f"encrypted/{filename}.enc"

    s3_download_logger.info(f"Verifying {filename} on S3...")

    # -------- Fetch metadata.json --------
    try:
        obj = s3.get_object(Bucket=bucket, Key=meta_key)
        metadata = json.loads(obj["Body"].read())
    except Exception as e:
        s3_download_logger.error(f"Cannot load metadata.json: {meta_key} – {e}")
        error_logger.error(f"metadata.json missing | {meta_key} | {e}")
        return False

    expected_sha = metadata.get("ciphertext_sha256")
    if not expected_sha:
        s3_download_logger.error("Missing ciphertext_sha256 in metadata.json")
        return False

    # -------- Fetch S3 object metadata SHA256 --------
    try:
        head = s3.head_object(Bucket=bucket, Key=enc_key)
        remote_sha = head.get("Metadata", {}).get("sha256")
    except Exception as e:
        s3_download_logger.error(f"Cannot read S3 metadata: {enc_key} – {e}")
        return False

    if not remote_sha:
        s3_download_logger.error("Missing sha256 in S3 metadata")
        return False

    # -------- Compare --------
    if expected_sha != remote_sha:
        s3_download_logger.error(
            f"S3 integrity FAIL | file={filename} | expected={expected_sha} | actual={remote_sha}"
        )
        error_logger.error(
            f"S3 integrity FAIL | file={filename} | expected={expected_sha} | actual={remote_sha}"
        )
        return False

    s3_download_logger.info(f"S3 integrity OK: {filename}")
    return True


# ============================================================
# DOWNLOAD FILE
# ============================================================
def download_s3_object(key, local_path):
    """Download single object from S3 with logging"""
    bucket = _get_bucket()
    s3 = _get_s3_client()
    
    try:
        s3.download_file(bucket, key, str(local_path))
        s3_download_logger.info(f"Downloaded {key}")
        return True
    except Exception as e:
        s3_download_logger.error(f"Download failed: {key} – {e}")
        error_logger.error(f"Download failed | {key} | {e}")
        return False


# ============================================================
# DOWNLOAD ONE FILE BUNDLE (with double integrity check)
# ============================================================
def download_file_pair(filename):
    """
    Download: .enc + .key.enc + .metadata.json
    
    Process:
    1. Verify integrity on S3 (before download)
    2. Download all files
    3. Verify integrity locally (after download)
    
    Args:
        filename: Base filename without extension (e.g., 'data.txt')
        
    Returns:
        True if successful, False otherwise
    """

    # ========== STEP 1: Verify on S3 ==========
    s3_download_logger.info(f"Step 1: Verifying {filename} on S3...")
    
    if not verify_on_s3(filename):
        s3_download_logger.error(f"Aborted: S3 integrity check failed for {filename}")
        return False

    # ========== STEP 2: Download files ==========
    s3_download_logger.info(f"Step 2: Downloading {filename}...")

    enc_key = f"encrypted/{filename}.enc"
    key_key = f"keys/{filename}.key.enc"
    meta_key = f"metadata/{filename}.metadata.json"

    local_enc = LOCAL_DIR / f"{filename}.enc"
    local_key = LOCAL_DIR / f"{filename}.key.enc"
    local_meta = LOCAL_DIR / f"{filename}.metadata.json"

    # Download all three files
    if not download_s3_object(enc_key, local_enc):
        return False
    if not download_s3_object(key_key, local_key):
        return False
    if not download_s3_object(meta_key, local_meta):
        return False

    # ========== STEP 3: Verify locally after download ==========
    s3_download_logger.info(f"Step 3: Verifying {filename} locally after download...")
    
    try:
        from app.utils.checksum import sha256_file
        
        # Load expected checksum from metadata
        with open(local_meta, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        expected_sha = metadata.get("ciphertext_sha256")
        if not expected_sha:
            raise ValueError("Missing ciphertext_sha256 in metadata")
        
        # Calculate actual checksum
        actual_sha = sha256_file(str(local_enc))
        
        if expected_sha != actual_sha:
            s3_download_logger.error(
                f"Local integrity FAIL | file={filename} | "
                f"expected={expected_sha} | actual={actual_sha}"
            )
            error_logger.error(
                f"Local integrity FAIL after download | file={filename} | "
                f"This may indicate corruption during download"
            )
            return False
        
        s3_download_logger.info(f"✓ Local integrity OK: {filename}")
        
    except Exception as e:
        s3_download_logger.error(f"Local verification failed: {e}")
        error_logger.error(f"Local verification error | {filename} | {e}")
        return False

    s3_download_logger.info(f"✓ Completed download for {filename} (verified)")
    return True


# ============================================================
# DOWNLOAD ALL ENCRYPTED FILES
# ============================================================
def download_all_encrypted():
    """Download all encrypted files from S3 with integrity checks"""
    bucket = _get_bucket()
    s3 = _get_s3_client()
    
    s3_download_logger.info(f"Listing encrypted objects in S3 bucket: {bucket}")

    try:
        objects = s3.list_objects_v2(Bucket=bucket, Prefix="encrypted/")
    except Exception as e:
        error_logger.error(f"Failed to list S3 objects: {e}")
        raise

    if "Contents" not in objects:
        s3_download_logger.warning("No encrypted files found in S3")
        return

    # Get base filenames
    basenames = []
    for obj in objects["Contents"]:
        if obj["Key"].endswith(".enc"):
            basename = os.path.basename(obj["Key"]).replace(".enc", "")
            basenames.append(basename)

    s3_download_logger.info(f"Found {len(basenames)} encrypted files")

    success_count = 0
    failed_count = 0

    for base in basenames:
        try:
            if download_file_pair(base):
                success_count += 1
            else:
                failed_count += 1
        except Exception as e:
            error_logger.error(f"Error downloading {base}: {e}")
            failed_count += 1

    s3_download_logger.info(
        f"Download completed: {success_count} success, {failed_count} failed"
    )

    if failed_count > 0:
        s3_download_logger.warning(f"{failed_count} files failed integrity check or download")


# ============================================================
# LIST S3 FILES (for GUI)
# ============================================================
def list_s3_files():
    """
    List all encrypted files on S3 with metadata
    
    Returns:
        List of dicts with file info:
        [
            {
                'filename': 'data.txt.enc',
                'size': 1234567,
                'modified': datetime,
                'integrity': 'OK' | 'FAIL' | 'UNKNOWN'
            }
        ]
    """
    bucket = _get_bucket()
    s3 = _get_s3_client()
    
    try:
        response = s3.list_objects_v2(Bucket=bucket, Prefix="encrypted/")
        
        if 'Contents' not in response:
            return []
        
        files = []
        for obj in response['Contents']:
            if not obj['Key'].endswith('.enc'):
                continue
            
            filename = obj['Key'].replace('encrypted/', '')
            base_name = filename.replace('.enc', '')
            
            # Check integrity
            try:
                integrity = 'OK' if verify_on_s3(base_name) else 'FAIL'
            except:
                integrity = 'UNKNOWN'
            
            files.append({
                'filename': filename,
                'size': obj['Size'],
                'modified': obj['LastModified'],
                'integrity': integrity
            })
        
        return files
        
    except Exception as e:
        error_logger.error(f"Failed to list S3 files: {e}")
        raise


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
        success = download_file_pair(filename)
        exit(0 if success else 1)
    
    if "--list" in args:
        files = list_s3_files()
        print(f"\nFound {len(files)} files on S3:\n")
        for f in files:
            print(f"  {f['filename']} - {f['size']/1024/1024:.2f}MB - {f['integrity']}")
        exit()

    print("Usage:")
    print("  python -m app.storage.s3_download --file <filename>")
    print("  python -m app.storage.s3_download --all")
    print("  python -m app.storage.s3_download --list")