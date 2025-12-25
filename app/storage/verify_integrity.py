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
    
    Args:
        enc_file_path: Path to encrypted file (e.g., data.txt.enc)
        
    Returns:
        True if verification passed, False otherwise
    """
    enc_file = Path(enc_file_path)
    
    # Skip .key.enc files - they don't have metadata
    if enc_file.name.endswith('.key.enc'):
        verify_logger.info(f"Skipped key file: {enc_file.name}")
        return True
    
    # Find metadata file
    base_name = enc_file.name.replace('.enc', '')
    metadata_path = enc_file.parent / f"{base_name}.metadata.json"

    if not metadata_path.exists():
        verify_error_logger.error(f"Missing metadata: {metadata_path}")
        return False

    try:
        # Load metadata
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)

        expected_sha = metadata.get("ciphertext_sha256")
        if not expected_sha:
            verify_error_logger.error(f"Missing ciphertext_sha256 in {metadata_path}")
            return False

        # Calculate actual SHA256
        actual_sha = sha256_file(str(enc_file))

        # Compare
        if actual_sha != expected_sha:
            verify_error_logger.error(
                f"Local verify FAIL | file={enc_file.name} | "
                f"expected={expected_sha} | actual={actual_sha}"
            )
            return False

        verify_logger.info(f"Local verify OK | file={enc_file.name}")
        return True
        
    except Exception as e:
        verify_error_logger.error(f"Verification error for {enc_file.name}: {e}")
        return False


def verify_on_s3(filename: str) -> bool:
    """
    Verify integrity of encrypted file on S3 without downloading it
    
    Args:
        filename: Base filename without extension (e.g., 'data.txt')
        
    Returns:
        True if verification passed, False otherwise
    """
    BUCKET = get_bucket_name()
    
    if not BUCKET:
        verify_error_logger.error("S3 bucket name not configured")
        return False
    
    s3 = boto3.client("s3")

    meta_key = f"metadata/{filename}.metadata.json"
    enc_key = f"encrypted/{filename}.enc"

    try:
        # Fetch metadata.json from S3
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
        # Get S3 object metadata (contains SHA256 we stored during upload)
        head = s3.head_object(Bucket=BUCKET, Key=enc_key)
        remote_sha = head.get("Metadata", {}).get("sha256")
    except Exception as e:
        verify_error_logger.error(f"Cannot read S3 metadata: {e}")
        return False

    if not remote_sha:
        verify_error_logger.error("S3 object metadata missing sha256")
        return False

    # Compare
    if expected_sha != remote_sha:
        verify_error_logger.error(
            f"S3 verify FAIL | file={filename}.enc | "
            f"expected={expected_sha} | actual={remote_sha}"
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
    
    Args:
        filename: Filename with or without extension (e.g., 'data.txt' or 'data.txt.enc')
        
    Returns:
        True if verification passed, False otherwise
    """
    # Normalize filename
    if not filename.endswith('.enc'):
        filename = f"{filename}.enc"
    
    enc_path = Path(DATA_DIR) / "encrypted" / filename
    
    if not enc_path.exists():
        verify_error_logger.error(f"File not found: {enc_path}")
        return False
    
    return verify_local(str(enc_path))


def verify_all_files():
    """
    Scheduler entrypoint.
    Verify all encrypted files in local encrypted folder.
    
    Returns:
        Dict with verification results
    """
    encrypted_dir = Path(DATA_DIR) / "encrypted"
    
    if not encrypted_dir.exists():
        verify_error_logger.error(f"Encrypted directory not found: {encrypted_dir}")
        return {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "files": []
        }
    
    results = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "files": []
    }
    
    # Get all .enc files (excluding .key.enc)
    enc_files = [
        f for f in encrypted_dir.glob("*.enc")
        if not f.name.endswith('.key.enc')
    ]
    
    verify_logger.info(f"Starting verification of {len(enc_files)} files...")
    
    for enc_file in enc_files:
        results["total"] += 1
        
        try:
            if verify_local(str(enc_file)):
                results["passed"] += 1
                results["files"].append({
                    "file": enc_file.name,
                    "status": "PASS"
                })
            else:
                results["failed"] += 1
                results["files"].append({
                    "file": enc_file.name,
                    "status": "FAIL"
                })
        except Exception as e:
            results["failed"] += 1
            results["files"].append({
                "file": enc_file.name,
                "status": "ERROR",
                "error": str(e)
            })
            verify_error_logger.error(f"Unexpected error verifying {enc_file.name}: {e}")
    
    # Log summary
    verify_logger.info(
        f"Verification completed: {results['passed']}/{results['total']} passed, "
        f"{results['failed']} failed, {results['skipped']} skipped"
    )
    
    return results


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    args = sys.argv

    if len(args) < 2:
        print("Usage:")
        print("  python -m app.storage.verify_integrity --local <path/to/file.enc>")
        print("  python -m app.storage.verify_integrity --s3 <filename_without_ext>")
        print("  python -m app.storage.verify_integrity --all")
        sys.exit(1)

    mode = args[1]

    if mode == "--local":
        if len(args) < 3:
            print("Error: Please specify file path")
            sys.exit(1)
        
        result = verify_local(args[2])
        sys.exit(0 if result else 1)

    elif mode == "--s3":
        if len(args) < 3:
            print("Error: Please specify filename")
            sys.exit(1)
        
        result = verify_on_s3(args[2])
        sys.exit(0 if result else 1)

    elif mode == "--all":
        results = verify_all_files()
        
        print("\n" + "="*60)
        print("VERIFICATION RESULTS")
        print("="*60)
        print(f"Total files: {results['total']}")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Skipped: {results['skipped']}")
        print("="*60)
        
        if results['files']:
            print("\nDetailed results:")
            for file_info in results['files']:
                status_symbol = "✓" if file_info['status'] == "PASS" else "✗"
                print(f"  {status_symbol} {file_info['file']}: {file_info['status']}")
                if 'error' in file_info:
                    print(f"      Error: {file_info['error']}")
        
        print()
        sys.exit(0 if results['failed'] == 0 else 1)

    else:
        print(f"Invalid option: {mode}")
        print("Use --local, --s3, or --all")
        sys.exit(1)