import os
import glob
import time
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
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
from app.logging_config import encryption_logger, error_logger


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
# STREAMING AES-GCM ENCRYPTION (WITH CHECKSUM)
# ============================================================
def encrypt_file(input_path, encrypted_path, encrypted_key_path, password):
    start = time.perf_counter()
    encryption_logger.info(f"START encrypt | file={input_path}")

    try:
        # Load RSA keys using password
        _, public_key = load_rsa_keys(password)

        # Generate AES key + nonce
        aes_key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        # RSA wrap AES key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)

        with open(input_path, "rb") as fin, open(encrypted_path, "wb") as fout:
            fout.write(nonce)
            fout.write(b"\x00" * TAG_SIZE)

            while chunk := fin.read(CHUNK_SIZE):
                fout.write(encryptor.update(chunk))

            fout.write(encryptor.finalize())
            tag = encryptor.tag

            # write TAG back
            fout.seek(NONCE_SIZE)
            fout.write(tag)

        # Save encrypted AES key
        with open(encrypted_key_path, "wb") as f:
            f.write(encrypted_aes_key)

        # Save metadata
        checksum = sha256_file(encrypted_path)
        metadata_path = encrypted_path.replace(".enc", ".metadata.json")

        metadata = {
            "ciphertext_sha256": checksum,
            "nonce": nonce.hex(),
            "tag": tag.hex(),
        }

        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=4)

        elapsed = time.perf_counter() - start
        encryption_logger.info(
            f"SUCCESS encrypt | file={input_path} | output={encrypted_path} | key={encrypted_key_path} | checksum={checksum} | time={elapsed:.2f}s"
        )
        print(f"[Encrypted OK] {input_path} → {encrypted_path} in {elapsed:.2f}s")

    except Exception as e:
        elapsed = time.perf_counter() - start
        error_logger.error(
            f"FAIL encrypt | file={input_path} | err={str(e)} | time={elapsed:.2f}s"
        )
        print(f"[ERROR] Encryption failed for {input_path}: {str(e)}")
        raise


# ============================================================
# ENCRYPT ALL FILES IN A FOLDER
# ============================================================
def encrypt_all_in_folder(input_folder, encrypted_folder, password):
    os.makedirs(encrypted_folder, exist_ok=True)

    files = [
        f for f in glob.glob(os.path.join(input_folder, "**/*"), recursive=True)
        if os.path.isfile(f)
    ]

    print(f"Found {len(files)} files. Starting encryption…")

    for file_path in files:
        name = os.path.basename(file_path)
        enc_path = os.path.join(encrypted_folder, f"{name}.enc")
        key_path = os.path.join(encrypted_folder, f"{name}.key.enc")

        encrypt_file(file_path, enc_path, key_path, password)

    print("✔ Done encrypting all files.")


# ============================================================
# MAIN ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import sys

    original = f"{DATA_DIR}/original"
    encrypted = f"{DATA_DIR}/encrypted"

    if not os.path.exists(f"{KEY_DIR}/rsa_private.pem"):
        raise ValueError("❌ RSA keys not found. Please run RSA key generation first.")

    args = sys.argv[1:]
    password = os.environ.get("RSA_PASSWORD", "test123")   # default for testing

    if "--all" in args:
        encrypt_all_in_folder(original, encrypted, password)
    else:
        sample = f"{original}/sample.txt"
        enc = f"{encrypted}/sample.txt.enc"
        key = f"{encrypted}/sample.txt.key.enc"

        print("No --all flag. Running sample encryption…")
        encrypt_file(sample, enc, key, password)
