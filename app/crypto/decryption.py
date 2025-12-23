import os
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.core.settings import DATA_DIR
from app.core.logging_config import decryption_logger, error_logger
from app.crypto.rsa_utils import load_private_key_by_version


# ============================================================
# HELPERS
# ============================================================
def load_metadata(enc_file: Path) -> dict:
    base = enc_file.name.replace(".enc", "")
    meta_file = enc_file.parent / f"{base}.metadata.json"

    if not meta_file.exists():
        raise FileNotFoundError(f"Metadata not found for {enc_file.name}")

    return json.loads(meta_file.read_text(encoding="utf-8"))


def decrypt_aes_key(key_file: Path, password: str, rsa_version: str) -> bytes:
    private_key = load_private_key_by_version(rsa_version, password)
    encrypted_key = key_file.read_bytes()

    return private_key.decrypt(
        encrypted_key,
        padding=__get_rsa_padding(),
    )


def __get_rsa_padding():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


# ============================================================
# DECRYPT FILE
# ============================================================
def decrypt_file(enc_file: Path, password: str):
    start = time.perf_counter()
    metadata = load_metadata(enc_file)

    rsa_version = metadata["key_version"]
    nonce = bytes.fromhex(metadata["nonce"])
    tag = bytes.fromhex(metadata["tag"])

    key_file = enc_file.with_suffix(".key.enc")

    aes_key = decrypt_aes_key(key_file, password, rsa_version)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
    )

    decryptor = cipher.decryptor()

    decrypted_dir = Path(DATA_DIR) / "decrypted"
    decrypted_dir.mkdir(parents=True, exist_ok=True)

    output_path = decrypted_dir / enc_file.name.replace(".enc", "")

    with open(enc_file, "rb") as f_in, open(output_path, "wb") as f_out:
        while chunk := f_in.read(1024 * 1024):
            f_out.write(decryptor.update(chunk))

        f_out.write(decryptor.finalize())
    elapsed = time.perf_counter() - start

    decryption_logger.info(f"Decrypted {enc_file.name} | time={elapsed:.2f}s")
    print(f"✔ Decrypted {enc_file.name}")


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Decrypt encrypted files")
    parser.add_argument("--all", action="store_true", help="Decrypt all files")

    args = parser.parse_args()

    if args.all:
        password = input("Enter RSA private key password: ").strip()

        encrypted_dir = Path(DATA_DIR) / "encrypted"

        for enc_file in encrypted_dir.glob("*.enc"):
            # ❗ CHỈ decrypt ciphertext, KHÔNG BAO GIỜ decrypt .key.enc
            if enc_file.name.endswith(".key.enc"):
                continue

            try:
                decrypt_file(enc_file, password)
            except Exception as e:
                error_logger.exception(f"Failed decrypting {enc_file.name}")
                print(f"✖ Failed decrypting {enc_file.name}: {type(e).__name__}")
