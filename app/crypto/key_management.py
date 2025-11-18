import os
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.settings import KEY_DIR, DATA_DIR
from app.logging_config import key_logger, error_logger
from app.crypto.rsa_utils import load_rsa_keys, generate_rsa_keys


# ============================================================
# HELPERS
# ============================================================
def find_all_encrypted_keys():
    """
    Trả về danh sách các file .key.enc trong /data/encrypted.
    """
    encrypted_folder = Path(DATA_DIR) / "encrypted"
    encrypted_folder.mkdir(parents=True, exist_ok=True)

    return list(encrypted_folder.glob("*.key.enc"))


def load_metadata(filepath: Path):
    """
    Load metadata JSON, dùng để biết file .enc nào kèm .key.enc nào.
    """
    meta_path = filepath.with_suffix(".metadata.json")
    if not meta_path.exists():
        raise FileNotFoundError(f"Metadata file missing: {meta_path}")
    return json.loads(meta_path.read_text())


# ============================================================
# ROTATE RSA KEYPAIR
# ============================================================
def rotate_keys(old_password: str):
    """
    Rotation RSA keypair:
    1. Load current RSA keypair (requires password)
    2. Generate new RSA keypair (ask for password again)
    3. Re-encrypt ALL AES keys using new public key
    4. Save new RSA keys
    5. Keep old RSA keys archived (optionally)
    """

    key_logger.info("=== Starting RSA Key Rotation ===")

    # -----------------------------
    # 1) Load old RSA private key
    # -----------------------------
    try:
        old_private_key, old_public_key = load_rsa_keys(old_password)
    except Exception as e:
        error_logger.error(f"Failed to load existing RSA keys: {e}")
        print("❌ Incorrect password. Rotation aborted.")
        return False

    print("✔ Old RSA key loaded.")

    # -----------------------------
    # 2) Ask for password for new private key
    # -----------------------------
    new_password = input("Enter password for NEW RSA private key: ").strip()
    if len(new_password) < 6:
        print("❌ Password too short. Rotation aborted.")
        return False

    # -----------------------------
    # 3) Generate new RSA keypair
    # -----------------------------
    print("Generating new RSA keypair...")
    generate_rsa_keys(new_password)
    print("✔ New RSA keypair generated.")

    # Load new keys back
    new_private_key, new_public_key = load_rsa_keys(new_password)

    # -----------------------------
    # 4) Re-encrypt all AES keys
    # -----------------------------
    print("Re-encrypting all AES keys with new RSA public key...")

    key_files = find_all_encrypted_keys()
    if not key_files:
        print("⚠ No key files found to rotate.")
        return True

    for old_key_file in key_files:
        try:
            # Load AES key encrypted by OLD RSA public key
            aes_key_encrypted = old_key_file.read_bytes()

            # Decrypt using old private key
            aes_key = old_private_key.decrypt(
                aes_key_encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Encrypt AES key using NEW public key
            new_aes_key_encrypted = new_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Overwrite file with new encrypted AES key
            old_key_file.write_bytes(new_aes_key_encrypted)

            key_logger.info(f"Rotated key: {old_key_file.name}")
            print(f"✔ Rotated: {old_key_file.name}")

        except Exception as e:
            error_logger.error(f"Failed rotating AES key {old_key_file}: {e}")
            print(f"❌ Failed rotating {old_key_file.name}")
            continue

    # -----------------------------
    # 5) Rotation completed
    # -----------------------------
    print("======================================")
    print("🎉 RSA Key Rotation Completed Successfully")
    print("======================================")

    key_logger.info("=== RSA Key Rotation Completed ===")
    return True
