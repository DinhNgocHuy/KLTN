import os
import json
import time
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.settings import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    CHUNK_SIZE,
    KEY_DIR,
    DATA_DIR,
)

from app.crypto.rsa_utils import load_rsa_keys
from app.logging_config import decryption_logger, error_logger

# ============================================================
# SHA256 CHECKSUM
# ============================================================
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ============================================================
# STREAMING AES-GCM DECRYPTION (WITH INTEGRITY CHECK)
# ============================================================
def decrypt_file(enc_path, key_path, output_path):
    start = time.perf_counter()
    decryption_logger.info(f"START decrypt | file={enc_path}")

    try:
        # ------------------------------------------------------------
        # 1) Load metadata (to verify ciphertext integrity)
        # ------------------------------------------------------------
        metadata_path = enc_path.replace(".enc", ".metadata.json")
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Missing metadata file: {metadata_path}")

        with open(metadata_path, "r") as f:
            metadata = json.load(f)

        expected_checksum = metadata.get("ciphertext_sha256")
        if not expected_checksum:
            raise RuntimeError("Metadata missing ciphertext SHA256 hash")

        # ------------------------------------------------------------
        # 2) Verify ciphertext checksum BEFORE decrypting
        # ------------------------------------------------------------
        actual_checksum = sha256_file(enc_path)

        if actual_checksum != expected_checksum:
            raise RuntimeError(
                f"Ciphertext integrity FAILED. expected={expected_checksum}, actual={actual_checksum}"
            )

        # ------------------------------------------------------------
        # 3) Load AES key (RSA-unwrapped)
        # ------------------------------------------------------------
        with open(key_path, "rb") as f:
            encrypted_aes_key = f.read()

        private_key, public_key = load_rsa_keys()

        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # ------------------------------------------------------------
        # 4) Start AES-GCM streaming decryption
        # ------------------------------------------------------------
        with open(enc_path, "rb") as fin:
            nonce = fin.read(NONCE_SIZE)
            tag = fin.read(TAG_SIZE)

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
            )
            decryptor = cipher.decryptor()

            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as fout:
                while chunk := fin.read(CHUNK_SIZE):
                    pt = decryptor.update(chunk)
                    if pt:
                        fout.write(pt)

                final_pt = decryptor.finalize()
                if final_pt:
                    fout.write(final_pt)

        elapsed = time.perf_counter() - start
        decryption_logger.info(
            f"SUCCESS decrypt | file={enc_path} | output={output_path} | time={elapsed:.2f}s"
        )
        print(f"[Decrypted OK] {enc_path} → {output_path} in {elapsed:.2f}s")

    except Exception as e:
        elapsed = time.perf_counter() - start
        error_logger.error(
            f"FAIL decrypt | file={enc_path} | err={str(e)} | time={elapsed:.2f}s"
        )
        print(f"[ERROR] Decryption failed for {enc_path} → {str(e)}")
        raise


# ============================================================
# MAIN ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import sys

    encrypted_folder = f"{DATA_DIR}/encrypted"
    restored_folder = f"{DATA_DIR}/restored"

    if len(sys.argv) < 2:
        print("Usage: python decrypt.py <file.enc>")
        exit(1)

    enc_file = sys.argv[1]
    base = enc_file.replace(".enc", "")

    key_file = base + ".key.enc"
    output_file = base.replace("/encrypted/", "/restored/")

    decrypt_file(enc_file, key_file, output_file)