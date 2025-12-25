import os
import glob
import time
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from app.utils.checksum import sha256_file
from app.crypto.rsa_utils import (
    get_current_rsa_version,
    load_public_key_by_version,
)

from app.core.settings import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    CRYPTO_CHUNK_SIZE,
    STREAM_BUFFER_SIZE,
    MAX_GCM_BYTES,
    KEY_DIR,
    DATA_DIR,
)

from app.core.logging_config import encryption_logger, error_logger


# ============================================================
# ENTRYPOINT – AUTO SELECT MODE
# ============================================================
def encrypt_file(input_path, output_base_dir, encrypted_key_path=None):
    """
    Main entry point for file encryption
    
    Args:
        input_path: Path to original file
        output_base_dir: Base directory (e.g., /data NOT /data/encrypted)
        encrypted_key_path: DEPRECATED - not used
    """
    file_size = os.path.getsize(input_path)
    
    encryption_logger.info(f"Encrypting {Path(input_path).name} ({file_size} bytes)")

    if file_size <= MAX_GCM_BYTES:
        encrypt_file_single_gcm(input_path, output_base_dir)
    else:
        encrypt_file_chunked(input_path, output_base_dir)


# ============================================================
# SINGLE-FILE AES-GCM (FILE <= 60GB)
# ============================================================
def encrypt_file_single_gcm(input_path, output_base_dir):
    """
    Encrypt file using single AES-GCM
    
    Structure created:
    output_base_dir/
    ├── encrypted/file.enc
    ├── keys/file.key.enc
    └── metadata/file.metadata.json
    """
    start = time.perf_counter()
    encryption_logger.info(f"START encrypt(single) | file={input_path}")

    try:
        # Get RSA key version
        key_version = get_current_rsa_version()
        public_key = load_public_key_by_version(key_version)

        # Generate AES key and nonce
        aes_key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        # Create cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        # Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # ============================================================
        # CREATE FOLDER STRUCTURE - ONLY 3 FOLDERS
        # ============================================================
        output_base = Path(output_base_dir)
        
        encrypted_dir = output_base / "encrypted"
        keys_dir = output_base / "keys"
        metadata_dir = output_base / "metadata"
        
        # Create only if not exists
        encrypted_dir.mkdir(exist_ok=True)
        keys_dir.mkdir(exist_ok=True)
        metadata_dir.mkdir(exist_ok=True)

        # Get filename only
        base_name = Path(input_path).name
        
        # Create file paths - FILES NOT FOLDERS
        encrypted_path = encrypted_dir / f"{base_name}.enc"
        key_path = keys_dir / f"{base_name}.key.enc"
        meta_path = metadata_dir / f"{base_name}.metadata.json"

        # Encrypt file content
        with open(input_path, "rb") as fin, open(encrypted_path, "wb") as fout:
            while buf := fin.read(STREAM_BUFFER_SIZE):
                fout.write(encryptor.update(buf))
            fout.write(encryptor.finalize())
            tag = encryptor.tag

        # Save encrypted AES key
        key_path.write_bytes(encrypted_aes_key)

        # Calculate checksum
        checksum = sha256_file(str(encrypted_path))

        # Create metadata
        metadata = {
            "mode": "aes-gcm-single",
            "algorithm": "AES-256-GCM",
            "ciphertext_sha256": checksum,
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "key_version": key_version,
            "encrypted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "original_file": base_name,
            "file_paths": {
                "encrypted": f"encrypted/{encrypted_path.name}",
                "key": f"keys/{key_path.name}",
                "metadata": f"metadata/{meta_path.name}"
            }
        }

        # Write metadata
        meta_path.write_text(json.dumps(metadata, indent=4), encoding='utf-8')

        # Verify
        if not encrypted_path.exists() or not key_path.exists() or not meta_path.exists():
            raise RuntimeError(f"Failed to create all files")

        elapsed = time.perf_counter() - start
        encryption_logger.info(f"SUCCESS | {base_name} | {elapsed:.2f}s")

    except Exception as e:
        error_logger.error(f"FAIL encrypt(single) | {input_path} | {e}", exc_info=True)
        raise


# ============================================================
# CHUNK-BASED AES-GCM (FILE > 60GB)
# ============================================================
def encrypt_file_chunked(input_path, output_base_dir):
    """Encrypt large file using chunked AES-GCM"""
    start = time.perf_counter()
    encryption_logger.info(f"START encrypt(chunked) | file={input_path}")

    try:
        key_version = get_current_rsa_version()
        public_key = load_public_key_by_version(key_version)

        aes_key = os.urandom(AES_KEY_SIZE)
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        output_base = Path(output_base_dir)
        encrypted_dir = output_base / "encrypted"
        keys_dir = output_base / "keys"
        metadata_dir = output_base / "metadata"
        
        encrypted_dir.mkdir(exist_ok=True)
        keys_dir.mkdir(exist_ok=True)
        metadata_dir.mkdir(exist_ok=True)

        base_name = Path(input_path).name
        chunks_dir = encrypted_dir / f"{base_name}.chunks"
        chunks_dir.mkdir(exist_ok=True)
        
        key_path = keys_dir / f"{base_name}.key.enc"
        meta_path = metadata_dir / f"{base_name}.metadata.json"

        key_path.write_bytes(encrypted_aes_key)

        chunk_index = 0
        chunk_meta = []

        with open(input_path, "rb") as fin:
            while True:
                nonce = os.urandom(NONCE_SIZE)
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
                encryptor = cipher.encryptor()

                bytes_in_chunk = 0
                chunk_path = chunks_dir / f"chunk_{chunk_index:06d}.enc"

                with open(chunk_path, "wb") as fout:
                    fout.write(nonce)
                    fout.write(b"\x00" * TAG_SIZE)

                    while bytes_in_chunk < CRYPTO_CHUNK_SIZE:
                        buf = fin.read(min(STREAM_BUFFER_SIZE, CRYPTO_CHUNK_SIZE - bytes_in_chunk))
                        if not buf:
                            break
                        fout.write(encryptor.update(buf))
                        bytes_in_chunk += len(buf)

                    if bytes_in_chunk == 0:
                        chunk_path.unlink()
                        break

                    fout.write(encryptor.finalize())
                    tag = encryptor.tag
                    fout.seek(NONCE_SIZE)
                    fout.write(tag)

                chunk_meta.append({
                    "chunk_index": chunk_index,
                    "size": bytes_in_chunk,
                    "file": chunk_path.name,
                })
                chunk_index += 1

        metadata = {
            "mode": "aes-gcm-chunked",
            "algorithm": "AES-256-GCM",
            "crypto_chunk_size": CRYPTO_CHUNK_SIZE,
            "stream_buffer_size": STREAM_BUFFER_SIZE,
            "total_chunks": chunk_index,
            "chunks": chunk_meta,
            "key_version": key_version,
            "encrypted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "original_file": base_name,
            "file_paths": {
                "encrypted": f"encrypted/{base_name}.chunks/",
                "key": f"keys/{key_path.name}",
                "metadata": f"metadata/{meta_path.name}"
            }
        }

        meta_path.write_text(json.dumps(metadata, indent=4), encoding='utf-8')

        elapsed = time.perf_counter() - start
        encryption_logger.info(f"SUCCESS chunked | {base_name} | {chunk_index} chunks | {elapsed:.2f}s")

    except Exception as e:
        error_logger.error(f"FAIL encrypt(chunked) | {input_path} | {e}", exc_info=True)
        raise


# ============================================================
# ENCRYPT ALL FILES
# ============================================================
def encrypt_all_in_folder(input_folder, output_base_dir):
    """Encrypt all files in a folder"""
    Path(output_base_dir).mkdir(parents=True, exist_ok=True)

    files = [
        f for f in glob.glob(os.path.join(input_folder, "**/*"), recursive=True)
        if os.path.isfile(f)
    ]

    encryption_logger.info(f"Found {len(files)} files to encrypt")

    success_count = 0
    failed_count = 0

    for file_path in files:
        try:
            encrypt_file(file_path, output_base_dir)
            success_count += 1
        except Exception as e:
            error_logger.error(f"Failed to encrypt {file_path}: {e}", exc_info=True)
            failed_count += 1

    encryption_logger.info(f"Batch completed: {success_count} success, {failed_count} failed")


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        raise RuntimeError("Usage: python -m app.crypto.encryption <input_file> | --all")

    if "--all" in sys.argv:
        original = Path(DATA_DIR) / "original"
        encrypted = Path(DATA_DIR)  # Base dir, not /encrypted
        encrypt_all_in_folder(str(original), str(encrypted))
        sys.exit(0)

    input_file = Path(sys.argv[1]).resolve()
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    encrypted_dir = Path(DATA_DIR)  # Base dir
    encrypt_file(str(input_file), str(encrypted_dir))