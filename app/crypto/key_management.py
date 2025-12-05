import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.settings import KEY_DIR, DATA_DIR
from app.logging_config import key_logger, error_logger
from app.crypto.rsa_utils import load_rsa_keys, generate_rsa_keys
from app.storage.s3_upload import upload_file_to_s3


# ============================================================
# HELPERS
# ============================================================
def find_all_encrypted_keys():
    """
    Trả về danh sách tất cả file *.key.enc trong data/encrypted.
    """
    encrypted_dir = Path(DATA_DIR) / "downloaded_encrypted"
    encrypted_dir.mkdir(parents=True, exist_ok=True)
    return list(encrypted_dir.glob("*.key.enc"))


# ============================================================
# ROTATE RSA KEYPAIR
# ============================================================
def rotate_keys(old_password: str):
    key_logger.info("=== Starting RSA Key Rotation ===")
    print("=== Starting RSA Key Rotation ===")

    # 1) Load old RSA key
    try:
        old_private, old_public = load_rsa_keys(old_password)
    except Exception:
        print("❌ Incorrect old password. Rotation aborted.")
        return False

    print("✔ Old RSA key loaded.")

    # 2) New password
    new_password = input("Enter NEW password for RSA private key: ").strip()
    if len(new_password) < 6:
        print("❌ Password too short (min 6 chars).")
        return False

    # 3) Generate new RSA keys
    print("Creating new RSA keypair...")
    try:
        generate_rsa_keys(new_password)
    except Exception as e:
        print(f"❌ Failed generating RSA keys: {e}")
        return False

    print("✔ New RSA keypair generated.")
    new_private, new_public = load_rsa_keys(new_password)

    # 4) Rotate all AES keys
    print("Re-encrypting all AES keys using new RSA public key...")
    key_files = find_all_encrypted_keys()

    if not key_files:
        print("⚠ No AES keys found. Nothing to rotate.")
        return True

    for key_file in key_files:
        try:
            encrypted_old = key_file.read_bytes()

            # decrypt AES key using old private key
            aes_key = old_private.decrypt(
                encrypted_old,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # encrypt AES key with new public key
            encrypted_new = new_public.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            key_file.write_bytes(encrypted_new)

            #Upload rotated key to S3
            upload_file_to_s3(
                local_path=str(key_file),
                s3_key=f"keys/{key_file.name}"
            )

            key_logger.info(f"Rotated AES key: {key_file.name}")
            print(f"✔ Rotated: {key_file.name}")

        except Exception as e:
            error_logger.error(f"Failed rotating {key_file}: {e}")
            print(f"❌ Failed rotating {key_file.name}")

    print("======================================")
    print("🎉 RSA Key Rotation Completed Successfully")
    print("======================================")

    key_logger.info("=== RSA Key Rotation Completed ===")
    return True


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RSA Key Management Tool")
    parser.add_argument("--generate", action="store_true", help="Generate RSA keypair")
    parser.add_argument("--rotate", action="store_true", help="Rotate RSA keypair")

    args = parser.parse_args()

    # -------- Generate Keys --------
    if args.generate:
        print("=== Generate RSA Keypair ===")
        pw = input("Enter password: ").strip()
        if len(pw) < 6:
            print("❌ Password too short.")
            exit(1)

        generate_rsa_keys(pw)
        print("🎉 RSA keypair created.")
        exit(0)

    # -------- Rotate Keys --------
    if args.rotate:
        old_pw = input("Enter OLD password: ").strip()
        rotate_keys(old_pw)
        exit(0)

    print("⚠ Missing argument. Use:")
    print("   --generate")
    print("   --rotate")
