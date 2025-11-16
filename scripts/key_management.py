# key_management.py (FULL VERSION WITH LOGGING)
# Features:
# - RSA-2048 master key generation
# - Private key protected using password (AES-GCM + PBKDF2)
# - Versioning: ACTIVE / RETIRED / DESTROYED
# - Logging for all key operations
# - CLI for generate / rotate / list / destroy
# - Compatible with encrypt/decrypt module

import os
import json
import shutil
import getpass
from datetime import datetime
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# ============================================================
# CONFIG
# ============================================================
KEYSTORE_DIR = "../keystore"
METADATA_FILE = f"{KEYSTORE_DIR}/key_metadata.json"
LOG_DIR = "../logs"

RSA_KEY_SIZE = 2048
KDF_ITERATIONS = 200000
AES_KEY_SIZE = 32

STATUS_ACTIVE = "ACTIVE"
STATUS_RETIRED = "RETIRED"
STATUS_DESTROYED = "DESTROYED"

# ============================================================
# LOGGING
# ============================================================
os.makedirs(LOG_DIR, exist_ok=True)

key_logger = logging.getLogger("key_management")
key_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(f"{LOG_DIR}/key_management.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
key_logger.addHandler(file_handler)

error_logger = logging.getLogger("key_management_error")
error_logger.setLevel(logging.ERROR)
err_handler = logging.FileHandler(f"{LOG_DIR}/key_error.log")
err_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
error_logger.addHandler(err_handler)


# ============================================================
# HELPERS
# ============================================================
def now():
    return datetime.utcnow().isoformat() + "Z"


def ensure_dirs():
    os.makedirs(KEYSTORE_DIR, exist_ok=True)

    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "w") as f:
            json.dump({"versions": {}}, f, indent=4)


def load_metadata():
    ensure_dirs()
    with open(METADATA_FILE, "r") as f:
        return json.load(f)


def save_metadata(data):
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


# ============================================================
# PASSWORD → KEY DERIVATION (PBKDF2)
# ============================================================
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())


# ============================================================
# PROTECT PRIVATE KEY USING AES-GCM
# ============================================================
def encrypt_private_key(private_pem: bytes, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_pem, None)
    return base64.b64encode(salt + nonce + ciphertext)


def decrypt_private_key(enc_data: bytes, password: str):
    try:
        raw = base64.b64decode(enc_data)
        salt = raw[:16]
        nonce = raw[16:28]
        ciphertext = raw[28:]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    except Exception:
        error_logger.error("Failed to decrypt RSA private key — wrong password or corrupted key")
        raise


# ============================================================
# CREATE NEW MASTER KEY VERSION
# ============================================================
def create_master_key(password: str):
    try:
        meta = load_metadata()
        versions = meta["versions"]
        new_ver = str(max([int(v) for v in versions] + [0]) + 1)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        encrypted_private = encrypt_private_key(private_pem, password)

        priv_path = f"{KEYSTORE_DIR}/rsa_private_v{new_ver}.enc"
        pub_path = f"{KEYSTORE_DIR}/rsa_public_v{new_ver}.pem"

        with open(priv_path, "wb") as f:
            f.write(encrypted_private)

        with open(pub_path, "wb") as f:
            f.write(public_pem)

        versions[new_ver] = {
            "public_key": pub_path,
            "private_key": priv_path,
            "status": STATUS_ACTIVE,
            "created_at": now(),
            "retired_at": None,
            "destroyed_at": None,
        }

        for v in versions:
            if v != new_ver and versions[v]["status"] == STATUS_ACTIVE:
                versions[v]["status"] = STATUS_RETIRED
                versions[v]["retired_at"] = now()

        save_metadata(meta)
        key_logger.info(f"Created RSA master key v{new_ver}")
        return new_ver

    except Exception as e:
        error_logger.error(f"Failed to create master key: {str(e)}")
        raise


# ============================================================
# LOAD A SPECIFIC MASTER KEY
# ============================================================
def load_master_key(version: str, password: str):
    meta = load_metadata()

    if version not in meta["versions"]:
        error_logger.error(f"Load failed — invalid version {version}")
        raise ValueError("Invalid key version")

    entry = meta["versions"][version]

    with open(entry["private_key"], "rb") as f:
        private_enc = f.read()

    private_pem = decrypt_private_key(private_enc, password)
    private_key = serialization.load_pem_private_key(private_pem, None)

    with open(entry["public_key"], "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    key_logger.info(f"Loaded RSA master key v{version}")
    return private_key, public_key, entry["status"]


# ============================================================
# LOAD ACTIVE MASTER KEY
# ============================================================
def load_active_master_key(password: str):
    meta = load_metadata()

    for v, entry in meta["versions"].items():
        if entry["status"] == STATUS_ACTIVE:
            return v, *load_master_key(v, password)

    error_logger.error("No ACTIVE master key found")
    raise RuntimeError("No ACTIVE master key found")


# ============================================================
# ENCRYPT / DECRYPT FILE AES KEY
# ============================================================
def encrypt_file_key(aes_key: bytes, password: str):
    version, priv, pub = load_active_master_key(password)

    encrypted = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    key_logger.info(f"Encrypted AES key using RSA v{version}")
    return version, encrypted


def decrypt_file_key(version: str, encrypted_key: bytes, password: str):
    priv, pub, status = load_master_key(version, password)

    if status == STATUS_DESTROYED:
        error_logger.error(f"Decrypt failed — key v{version} is DESTROYED")
        raise RuntimeError("Key destroyed — cannot decrypt")

    aes_key = priv.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    key_logger.info(f"Decrypted AES key using RSA v{version}")
    return aes_key


# ============================================================
# ROTATE MASTER KEY
# ============================================================
def rotate(password: str):
    key_logger.info("Rotation requested")
    return create_master_key(password)


# ============================================================
# DESTROY MASTER KEY
# ============================================================
def destroy(version: str):
    meta = load_metadata()

    if version not in meta["versions"]:
        error_logger.error(f"Destroy failed — invalid version {version}")
        raise ValueError("Invalid key version")

    entry = meta["versions"][version]

    DEST = f"{KEYSTORE_DIR}/destroyed"
    os.makedirs(DEST, exist_ok=True)

    # Move key files
    shutil.move(entry["private_key"], DEST)
    shutil.move(entry["public_key"], DEST)

    entry["status"] = STATUS_DESTROYED
    entry["destroyed_at"] = now()
    save_metadata(meta)

    key_logger.warning(f"Key version v{version} DESTROYED")


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys

    print(">>> Running key_management.py from:", os.path.abspath(__file__))
    args = sys.argv[1:] if len(sys.argv) > 1 else []

    if "--generate" in args:
        pw = getpass.getpass("Enter master key password: ")
        create_master_key(pw)

    elif "--rotate" in args:
        pw = getpass.getpass("Enter master key password: ")
        rotate(pw)

    elif "--destroy" in args:
        if len(args) < 2:
            print("Usage: python key_management.py --destroy <version>")
            exit(1)
        version = args[1]
        destroy(version)

    elif "--list" in args:
        meta = load_metadata()
        print(json.dumps(meta, indent=4))

    else:
        print(
            """
Usage:
    python key_management.py --generate       # Create first master key
    python key_management.py --rotate         # Rotate master key
    python key_management.py --destroy v1     # Destroy key version
    python key_management.py --list           # Show metadata
            """
        )