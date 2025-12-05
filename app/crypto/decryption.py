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
    CHUNK_SIZE,
    DATA_DIR,
)
from app.crypto.rsa_utils import load_private_key
from app.logging_config import decryption_logger, error_logger
from app.utils.checksum import sha256_file


# ============================================================
# DECRYPT ONE FILE
# ============================================================
def decrypt_file(cipher_path, key_path, meta_path, password):
    start = time.perf_counter()

    try:
        filename = Path(cipher_path).name.replace(".enc", "")
        out_path = Path(DATA_DIR) / "decrypted" / filename
        out_path.parent.mkdir(parents=True, exist_ok=True)

        print(f"\n=== DECRYPTING: {filename} ===")

        # ------------------------------------------------------------
        # Load metadata
        # ------------------------------------------------------------
        if not Path(meta_path).exists():
            print("❌ Missing metadata file")
            return False

        metadata = json.loads(Path(meta_path).read_text())

        for req in ["ciphertext_sha256", "nonce", "tag"]:
            if req not in metadata:
                print(f"❌ metadata.json missing field: {req}")
                return False

        nonce = bytes.fromhex(metadata["nonce"])
        tag = bytes.fromhex(metadata["tag"])
        expected_sha = metadata["ciphertext_sha256"]

        if len(nonce) != NONCE_SIZE:
            print("❌ Nonce size mismatch")
            return False
        if len(tag) != TAG_SIZE:
            print("❌ Tag size mismatch")
            return False

        # ------------------------------------------------------------
        # Verify SHA256 of ciphertext
        # ------------------------------------------------------------
        actual_sha = sha256_file(cipher_path)
        if actual_sha != expected_sha:
            print("❌ Ciphertext corrupted — SHA checksum mismatch!")
            error_logger.error(
                f"Cipher mismatch | file={cipher_path} | expected={expected_sha} | actual={actual_sha}"
            )
            return False

        print("✓ Ciphertext integrity OK")

        # ------------------------------------------------------------
        # Load RSA private key
        # ------------------------------------------------------------
        try:
            private_key = load_private_key(password)
        except:
            print("❌ Wrong RSA password or private key corrupted")
            return False

        # ------------------------------------------------------------
        # Load encrypted AES key
        # ------------------------------------------------------------
        encrypted_aes_key = Path(key_path).read_bytes()

        # RSA decrypt AES key
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except:
            print("❌ Wrong .key.enc file or RSA key mismatch")
            return False

        if len(aes_key) != AES_KEY_SIZE:
            print("❌ Invalid AES key size")
            return False

        # ------------------------------------------------------------
        # AES-GCM streaming decrypt
        # ------------------------------------------------------------
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
        ).decryptor()

        with open(cipher_path, "rb") as fin, open(out_path, "wb") as fout:
            fin.seek(NONCE_SIZE + TAG_SIZE)  # skip NONCE + TAG

            while chunk := fin.read(CHUNK_SIZE):
                fout.write(decryptor.update(chunk))

            # finalize AES-GCM (auth check)
            try:
                decryptor.finalize()
            except:
                print("❌ Authentication TAG mismatch — file was modified!")
                error_logger.error(f"TAG mismatch | file={cipher_path}")
                return False

        elapsed = time.perf_counter() - start
        print(f"✔ Decryption OK → {out_path} ({elapsed:.2f}s)")
        decryption_logger.info(f"Success | file={cipher_path} | output={out_path} | {elapsed:.2f}s")

        return True

    except Exception as e:
        print(f"❌ Decryption error: {e}")
        error_logger.error(f"Decrypt error | file={cipher_path} | {e}")
        return False



# ============================================================
# DECRYPT ALL
# ============================================================
def decrypt_all(password):
    enc_folder = Path(DATA_DIR) / "downloaded_encrypted"

    # Chỉ decrypt file .enc thật sự, KHÔNG decrypt .key.enc
    cipher_files = [
        f for f in enc_folder.glob("*.enc")
        if not f.name.endswith(".key.enc")
    ]

    print(f"Found {len(cipher_files)} encrypted files.")

    for cipher_file in cipher_files:
        base = cipher_file.stem  # remove .enc
        key_file = enc_folder / f"{base}.key.enc"
        meta_file = enc_folder / f"{base}.metadata.json"

        decrypt_file(cipher_file, key_file, meta_file, password)



# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    password = input("Enter RSA private key password: ").strip()

    # Decrypt ALL
    if "--all" in args:
        decrypt_all(password)
        exit()

    # Decrypt one file
    if "--file" in args:
        i = args.index("--file")
        fname = args[i + 1]

        cipher_path = Path(DATA_DIR) / "encrypted" / f"{fname}.enc"
        key_path    = Path(DATA_DIR) / "encrypted" / f"{fname}.key.enc"
        meta_path   = Path(DATA_DIR) / "encrypted" / f"{fname}.metadata.json"

        decrypt_file(cipher_path, key_path, meta_path, password)
        exit()

    print("Usage:")
    print("  python -m app.crypto.decryption --file <filename>")
    print("  python -m app.crypto.decryption --all")