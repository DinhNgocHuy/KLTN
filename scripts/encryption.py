import os
import glob
import time
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from encryption_config import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    CHUNK_SIZE,
    KEY_DIR,
    DATA_DIR,
)

from rsa_utils import load_rsa_keys, generate_rsa_keys
from logging_config import encryption_logger, error_logger

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
# 1) STREAMING AES-GCM ENCRYPTION (WITH CHECKSUM)
# ============================================================
def encrypt_file(input_path, encrypted_path, encrypted_key_path):
    start = time.perf_counter()
    encryption_logger.info(f"START encrypt | file={input_path}")

    try:
        # 1️⃣ Generate AES key + nonce
        aes_key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
        )
        encryptor = cipher.encryptor()

        # 2️⃣ Re-wrap AES key using RSA public key
        _, public_key = load_rsa_keys()
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 3️⃣ Streaming encryption
        os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)

        with open(input_path, "rb") as fin, open(encrypted_path, "wb") as fout:

            fout.write(nonce)                 # Write NONCE
            fout.write(b"\x00" * TAG_SIZE)    # Placeholder for TAG

            while chunk := fin.read(CHUNK_SIZE):
                ct = encryptor.update(chunk)
                if ct:
                    fout.write(ct)

            final_ct = encryptor.finalize()
            if final_ct:
                fout.write(final_ct)

            tag = encryptor.tag

            # Write TAG back into placeholder
            fout.seek(NONCE_SIZE)
            fout.write(tag)

        # 4️⃣ Save RSA-encrypted AES key
        with open(encrypted_key_path, "wb") as f:
            f.write(encrypted_aes_key)

        # 5️⃣ Calculate SHA256 checksum of encrypted file
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
        print(f"[ERROR] Encryption failed for {input_path} → {str(e)}")
        raise


# ============================================================
# 2) ENCRYPT ALL FILES IN A FOLDER
# ============================================================
def encrypt_all_in_folder(input_folder, encrypted_folder):
    os.makedirs(encrypted_folder, exist_ok=True)

    files = glob.glob(os.path.join(input_folder, "**/*"), recursive=True)
    files = [f for f in files if os.path.isfile(f)]

    print(f"Found {len(files)} files. Starting encryption…")

    for file_path in files:
        name = os.path.basename(file_path)
        enc_path = os.path.join(encrypted_folder, f"{name}.enc")
        key_path = os.path.join(encrypted_folder, f"{name}.key.enc")

        encrypt_file(file_path, enc_path, key_path)

    print("✔ Done encrypting all files.")


# ============================================================
# 3) MAIN ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import sys

    original = f"{DATA_DIR}/original"
    encrypted = f"{DATA_DIR}/encrypted"

    # If no RSA keypair found → generate new one
    if not os.path.exists(f"{KEY_DIR}/rsa_private.pem"):
        print("RSA keypair not found → generating new keypair...")
        generate_rsa_keys()

    args = sys.argv[1:] if len(sys.argv) > 1 else []

    if "--all" in args:
        encrypt_all_in_folder(original, encrypted)
    else:
        sample = f"{original}/sample.txt"
        enc = f"{encrypted}/sample.txt.enc"
        key = f"{encrypted}/sample.txt.key.enc"

        print("No --all flag. Running sample encryption…")
        encrypt_file(sample, enc, key)