import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.core.settings import KEY_DIR, DATA_DIR
from app.core.logging_config import key_logger, error_logger
from app.crypto.rsa_utils import (
    load_private_key_by_version,
    load_public_key_by_version,
    generate_rsa_keys,
    get_current_rsa_version,
    set_current_rsa_version,
)
from app.storage.s3_upload import upload_file_to_s3

# ============================================================
# HELPERS
# ============================================================
def find_all_encrypted_keys():
    """
    Trả về danh sách tất cả file *.key.enc trong data/encrypted
    """
    encrypted_dir = Path(DATA_DIR) / "encrypted"
    encrypted_dir.mkdir(parents=True, exist_ok=True)
    return list(encrypted_dir.glob("*.key.enc"))


def load_metadata(key_file: Path) -> dict:
    base = key_file.name.replace(".key.enc", "")
    meta_file = key_file.parent / f"{base}.metadata.json"

    if not meta_file.exists():
        raise FileNotFoundError(f"Metadata not found for {key_file.name}")

    return json.loads(meta_file.read_text(encoding="utf-8"))

def save_metadata(key_file: Path, metadata: dict):
    base = key_file.name.replace(".key.enc", "")
    meta_file = key_file.parent / f"{base}.metadata.json"

    meta_file.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8"
    )

    upload_file_to_s3(
        local_path=str(meta_file),
        s3_key=f"metadata/{meta_file.name}"
    )

# ============================================================
# ROTATE RSA KEYS (ENVELOPE ROTATION)
# ============================================================
def rotate_keys(old_password: str):
    key_logger.info("=== Starting RSA Key Rotation ===")
    print("=== Starting RSA Key Rotation ===")

    # --------------------------------------------------------
    # 1. Load current (old) RSA version
    # --------------------------------------------------------
    old_version = get_current_rsa_version()
    print(f"Current RSA version: {old_version}")

    try:
        old_private = load_private_key_by_version(old_version, old_password)
    except Exception:
        print("Incorrect password or failed loading old private key.")
        return False

    # --------------------------------------------------------
    # 2. Create new RSA version
    # --------------------------------------------------------
    new_version = f"v{int(old_version[1:]) + 1}"

    new_password = input(f"Enter NEW password for RSA {new_version}: ").strip()
    if len(new_password) < 6:
        print("Password too short (min 6 chars).")
        return False

    print(f"Generating new RSA keypair {new_version}...")
    generate_rsa_keys(new_password, new_version)

    new_private = load_private_key_by_version(new_version, new_password)
    new_public = load_public_key_by_version(new_version)

    print(f"✔ RSA keypair {new_version} generated.")

    # --------------------------------------------------------
    # 3. Rotate all AES keys (re-wrap only)
    # --------------------------------------------------------
    key_files = find_all_encrypted_keys()
    if not key_files:
        print("No encrypted AES keys found. Nothing to rotate.")
        return True

    for key_file in key_files:
        try:
            metadata = load_metadata(key_file)

            if metadata.get("key_version") != old_version:
                # Skip keys already rotated
                continue

            encrypted_old = key_file.read_bytes()

            # decrypt AES key using old RSA private key
            aes_key = old_private.decrypt(
                encrypted_old,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # encrypt AES key using new RSA public key
            encrypted_new = new_public.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # verify
            test = new_private.decrypt(
                encrypted_new,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            if test != aes_key:
                raise ValueError("AES key verification failed")

            # atomic replace
            tmp_file = key_file.with_suffix(".key.enc.tmp")
            tmp_file.write_bytes(encrypted_new)
            tmp_file.replace(key_file)

            # update metadata
            metadata["key_version"] = new_version
            save_metadata(key_file, metadata)

            # upload rotated key
            upload_file_to_s3(
                local_path=str(key_file),
                s3_key=f"keys/{key_file.name}"
            )

            key_logger.info(f"Rotated AES key {key_file.name} → {new_version}")
            print(f"✔ Rotated {key_file.name}")

        except Exception as e:
            error_logger.exception(f"Failed rotating {key_file.name}")
            print(f"✖ Failed rotating {key_file.name}: {e}")


    # --------------------------------------------------------
    # 4. Switch current RSA version
    # --------------------------------------------------------
    set_current_rsa_version(new_version)

    key_logger.info(f"=== RSA Rotation completed: {old_version} → {new_version} ===")
    print("======================================")
    print("RSA Key Rotation Completed Successfully")
    print("======================================")
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

    if args.generate:
        pw = input("Enter password for RSA v1: ").strip()
        if len(pw) < 6:
            print("Password too short.")
            exit(1)

        generate_rsa_keys(pw, "v1")
        set_current_rsa_version("v1")
        print("✔ RSA keypair v1 created.")
        exit(0)

    if args.rotate:
        old_pw = input("Enter OLD RSA password: ").strip()
        rotate_keys(old_pw)
        exit(0)

    print("Usage:")
    print("  --generate")
    print("  --rotate")
