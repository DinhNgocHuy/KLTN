import os
import glob
import time
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
from app.utils.checksum import sha256_file


# ============================================================
# ENTRYPOINT – AUTO SELECT MODE
# ============================================================
def encrypt_file(input_path, encrypted_path, encrypted_key_path):
    file_size = os.path.getsize(input_path)

    if file_size <= MAX_GCM_BYTES:
        encrypt_file_single_gcm(input_path, encrypted_path, encrypted_key_path)
    else:
        encrypt_file_chunked(input_path, encrypted_path, encrypted_key_path)


# ============================================================
# SINGLE-FILE AES-GCM (FILE <= 60GB)
# ============================================================
def encrypt_file_single_gcm(input_path, encrypted_path, encrypted_key_path):
    start = time.perf_counter()
    encryption_logger.info(f"START encrypt(single) | file={input_path}")

    try:
        key_version = get_current_rsa_version()
        public_key = load_public_key_by_version(key_version)

        aes_key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        Path(encrypted_path).parent.mkdir(parents=True, exist_ok=True)

        with open(input_path, "rb") as fin, open(encrypted_path, "wb") as fout:
            while buf := fin.read(STREAM_BUFFER_SIZE):
                fout.write(encryptor.update(buf))

            fout.write(encryptor.finalize())
            tag = encryptor.tag
            
        Path(encrypted_key_path).write_bytes(encrypted_aes_key)

        checksum = sha256_file(encrypted_path)
        meta_path = encrypted_path.replace(".enc", ".metadata.json")
        metadata = {
            "mode": "aes-gcm-single",
            "ciphertext_sha256": checksum,
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "key_version": key_version,
        }
        Path(meta_path).write_text(json.dumps(metadata, indent=4))

        elapsed = time.perf_counter() - start
        encryption_logger.info(
            f"SUCCESS encrypt(single) | file={input_path} | time={elapsed:.2f}s"
        )

    except Exception as e:
        error_logger.error(f"FAIL encrypt(single) | file={input_path} | err={e}")
        raise

# ============================================================
# CHUNK-BASED AES-GCM (FILE > 60GB)
# ============================================================
def encrypt_file_chunked(input_path, encrypted_base_dir, encrypted_key_path):
    start = time.perf_counter()
    encryption_logger.info(f"START encrypt(chunked) | file={input_path}")

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

    # ✅ LUÔN ghi key ra encrypted_folder
    Path(encrypted_key_path).write_bytes(encrypted_aes_key)

    base_name = Path(input_path).name
    out_dir = Path(encrypted_base_dir).parent / f"{base_name}.chunks"
    out_dir.mkdir(parents=True, exist_ok=True)

    chunk_index = 0
    chunk_meta = []

    with open(input_path, "rb") as fin:
        while True:
            nonce = os.urandom(NONCE_SIZE)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            bytes_in_chunk = 0
            chunk_path = out_dir / f"chunk_{chunk_index:06d}.enc"

            with open(chunk_path, "wb") as fout:
                fout.write(nonce)
                fout.write(b"\x00" * TAG_SIZE)

                while bytes_in_chunk < CRYPTO_CHUNK_SIZE:
                    buf = fin.read(
                        min(STREAM_BUFFER_SIZE, CRYPTO_CHUNK_SIZE - bytes_in_chunk)
                    )
                    if not buf:
                        break

                    fout.write(encryptor.update(buf))
                    bytes_in_chunk += len(buf)

                if bytes_in_chunk == 0:
                    break

                fout.write(encryptor.finalize())
                tag = encryptor.tag

                fout.seek(NONCE_SIZE)
                fout.write(tag)

            chunk_meta.append(
                {
                    "chunk_index": chunk_index,
                    "size": bytes_in_chunk,
                    "file": chunk_path.name,
                }
            )

            chunk_index += 1

    header = {
        "mode": "aes-gcm-chunked",
        "algorithm": "AES-256-GCM",
        "crypto_chunk_size": CRYPTO_CHUNK_SIZE,
        "stream_buffer_size": STREAM_BUFFER_SIZE,
        "total_chunks": chunk_index,
        "chunks": chunk_meta,
    }

    (out_dir / "header.json").write_text(json.dumps(header, indent=4))

    elapsed = time.perf_counter() - start
    encryption_logger.info(
        f"SUCCESS encrypt(chunked) | file={input_path} | chunks={chunk_index} | time={elapsed:.2f}s"
    )


# ============================================================
# ENCRYPT ALL FILES
# ============================================================
def encrypt_all_in_folder(input_folder, encrypted_folder):
    Path(encrypted_folder).mkdir(parents=True, exist_ok=True)

    files = [
        f
        for f in glob.glob(os.path.join(input_folder, "**/*"), recursive=True)
        if os.path.isfile(f)
    ]

    encryption_logger.info(f"Found {len(files)} files to encrypt")

    for file_path in files:
        name = os.path.basename(file_path)
        enc_path = os.path.join(encrypted_folder, f"{name}.enc")
        key_path = os.path.join(encrypted_folder, f"{name}.key.enc")

        encrypt_file(file_path, enc_path, key_path)


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        raise RuntimeError(
            "Usage: python -m app.crypto.encryption <input_file> | --all"
        )

    if "--all" in sys.argv:
        original = Path(DATA_DIR) / "original"
        encrypted = Path(DATA_DIR) / "encrypted"
        encrypt_all_in_folder(str(original), str(encrypted))
        sys.exit(0)

    # encrypt single file
    input_file = Path(sys.argv[1]).resolve()
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    encrypted_dir = Path(DATA_DIR) / "encrypted"
    encrypted_dir.mkdir(parents=True, exist_ok=True)

    encrypted_file = encrypted_dir / f"{input_file.name}.enc"
    encrypted_key = encrypted_dir / f"{input_file.name}.key.enc"

    encrypt_file(
        str(input_file),
        str(encrypted_file),
        str(encrypted_key),
    )

