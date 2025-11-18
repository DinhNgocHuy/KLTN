import os
import json
import hashlib
import sys
import logging

# ============================================================
# LOGGING
# ============================================================
LOG_DIR = "../logs"
os.makedirs(LOG_DIR, exist_ok=True)

verify_logger = logging.getLogger("verify_integrity")
verify_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(f"{LOG_DIR}/verify_integrity.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
verify_logger.addHandler(file_handler)

verify_error_logger = logging.getLogger("verify_integrity_error")
verify_error_logger.setLevel(logging.ERROR)
err_handler = logging.FileHandler(f"{LOG_DIR}/verify_error.log")
err_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
verify_error_logger.addHandler(err_handler)

# ============================================================
# CHECKSUM FUNCTION
# ============================================================
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

# ============================================================
# VERIFY INTEGRITY
# ============================================================
def verify_integrity(enc_file_path):
    base = enc_file_path.replace(".enc", "")
    metadata_path = base + ".metadata.json"

    if not os.path.exists(metadata_path):
        verify_error_logger.error(f"Metadata missing for file: {enc_file_path}")
        print("[!] Metadata file not found:", metadata_path)
        return False

    with open(metadata_path, "r") as f:
        metadata = json.load(f)

    expected_sha = metadata.get("plaintext_sha256")
    if not expected_sha:
        verify_error_logger.error(f"No checksum stored in metadata for {enc_file_path}")
        print("[!] No checksum found inside metadata.")
        return False

    actual_sha = sha256_file(enc_file_path)

    verify_logger.info(
        f"Verify file={enc_file_path} | expected={expected_sha} | actual={actual_sha}"
    )

    if expected_sha == actual_sha:
        verify_logger.info(f"Integrity OK for file={enc_file_path}")
        print("[✓] FILE INTEGRITY OK — No tampering detected.")
        return True
    else:
        verify_error_logger.error(
            f"Integrity FAILED for file={enc_file_path} | expected={expected_sha} | actual={actual_sha}"
        )
        print("[✗] FILE CORRUPTED — Integrity failed!")
        return False

# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_integrity.py <file.enc>")
        sys.exit(1)

    verify_integrity(sys.argv[1])
