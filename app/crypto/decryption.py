import os
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.settings import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    STREAM_BUFFER_SIZE,
    DATA_DIR,
)
from app.crypto.rsa_utils import load_private_key
from app.logging_config import decryption_logger, error_logger
from app.utils.checksum import sha256_file


# ============================================================
# SINGLE FILE AES-GCM DECRYPT
# ============================================================
def decrypt_file_single(cipher_path, key_path, meta_path, private_key):
    start = time.perf_counter()

    filename = Path(cipher_path).name.replace(".enc", "")
    out_path = Path(DATA_DIR) / "decrypted" / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n=== DECRYPTING (single): {filename} ===")

    if not meta_path.exists():
        print("Missing metadata file")
        return False

    metadata = json.loads(meta_path.read_text())
    nonce = bytes.fromhex(metadata["nonce"])
    tag = bytes.fromhex(metadata["tag"])
    expected_sha = metadata["ciphertext_sha256"]

    # Verify ciphertext integrity
    actual_sha = sha256_file(cipher_path)
    if actual_sha != expected_sha:
        print("Ciphertext corrupted (SHA256 mismatch)")
        return False

    encrypted_aes_key = key_path.read_bytes()
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
    ).decryptor()

    with open(cipher_path, "rb") as fin, open(out_path, "wb") as fout:
        fin.seek(NONCE_SIZE + TAG_SIZE)
        while buf := fin.read(STREAM_BUFFER_SIZE):
            fout.write(decryptor.update(buf))

        try:
            decryptor.finalize()
        except Exception:
            print("Authentication TAG mismatch")
            return False

    elapsed = time.perf_counter() - start
    print(f"✔ OK → {out_path} ({elapsed:.2f}s)")
    decryption_logger.info(f"Single decrypt OK | {filename} | {elapsed:.2f}s")
    return True


# ============================================================
# CHUNK-BASED AES-GCM DECRYPT
# ============================================================
def decrypt_file_chunked(base_name, encrypted_dir, private_key):
    start = time.perf_counter()

    print(f"\n=== DECRYPTING (chunked): {base_name} ===")

    chunk_dir = encrypted_dir / f"{base_name}.chunks"
    header_path = chunk_dir / "header.json"
    key_path = encrypted_dir / f"{base_name}.key.enc"

    if not header_path.exists():
        print("Missing header.json for chunked file")
        return False

    header = json.loads(header_path.read_text())

    encrypted_aes_key = key_path.read_bytes()
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    out_path = Path(DATA_DIR) / "decrypted" / base_name
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "wb") as fout:
        for chunk in header["chunks"]:
            chunk_file = chunk_dir / chunk["file"]

            with open(chunk_file, "rb") as fin:
                nonce = fin.read(NONCE_SIZE)
                tag = fin.read(TAG_SIZE)
                ciphertext = fin.read()

            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
            ).decryptor()

            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            except Exception:
                print(f"TAG mismatch in chunk {chunk['file']}")
                return False

            fout.write(plaintext)

    elapsed = time.perf_counter() - start
    print(f"✔ OK → {out_path} ({elapsed:.2f}s)")
    decryption_logger.info(f"Chunked decrypt OK | {base_name} | {elapsed:.2f}s")
    return True


# ============================================================
# AUTO DETECT + DECRYPT
# ============================================================
def decrypt_all(password):
    encrypted_dir = Path(DATA_DIR) / "encrypted"
    private_key = load_private_key(password)

    print("Scanning encrypted directory...")

    # --------------------------------------------------
    # 1. Collect ALL chunked base names (SOURCE OF TRUTH)
    # --------------------------------------------------
    chunked_bases = {
        d.name.replace(".chunks", "")
        for d in encrypted_dir.glob("*.chunks")
        if d.is_dir()
    }

    # --------------------------------------------------
    # 2. Decrypt CHUNKED files FIRST
    # --------------------------------------------------
    for base_name in sorted(chunked_bases):
        decrypt_file_chunked(base_name, encrypted_dir, private_key)

    # --------------------------------------------------
    # 3. Decrypt SINGLE files (ABSOLUTE SAFE)
    # --------------------------------------------------
    for cipher_file in encrypted_dir.glob("*.enc"):
        # ❌ Never decrypt key files
        if cipher_file.name.endswith(".key.enc"):
            continue

        base = cipher_file.stem

        # 🔒 HARD BLOCK: if chunked exists, NEVER single-decrypt
        if base in chunked_bases:
            continue

        key_file = encrypted_dir / f"{base}.key.enc"
        meta_file = encrypted_dir / f"{base}.metadata.json"

        decrypt_file_single(cipher_file, key_file, meta_file, private_key)


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys

    password = input("Enter RSA private key password: ").strip()

    if "--all" in sys.argv:
        decrypt_all(password)
        exit()

    if "--file" in sys.argv:
        i = sys.argv.index("--file")
        fname = sys.argv[i + 1]

        encrypted_dir = Path(DATA_DIR) / "encrypted"
        private_key = load_private_key(password)

        if (encrypted_dir / f"{fname}.chunks").exists():
            decrypt_file_chunked(fname, encrypted_dir, private_key)
        else:
            decrypt_file_single(
                encrypted_dir / f"{fname}.enc",
                encrypted_dir / f"{fname}.key.enc",
                encrypted_dir / f"{fname}.metadata.json",
                private_key,
            )
        exit()

    print("Usage:")
    print("  python -m app.crypto.decryption --all")
    print("  python -m app.crypto.decryption --file <filename>")
