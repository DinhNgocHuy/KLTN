import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from app.settings import KEY_DIR
from app.logging_config import key_logger, error_logger


# ============================================================
# GENERATE RSA KEYPAIR (PRIVATE KEY IS PASSWORD-PROTECTED)
# ============================================================
def generate_rsa_keys(password: str):
    """
    Generate RSA-4096 private/public keypair.
    Private key is encrypted using the given password.
    """

    if not password or len(password) < 6:
        raise ValueError("Password must be >= 6 characters.")

    key_logger.info("Generating RSA keypair (password protected)...")

    Path(KEY_DIR).mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()

    # ===== Save PRIVATE KEY (Encrypted PKCS#8) =====
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    (Path(KEY_DIR) / "rsa_private.pem").write_bytes(private_pem)

    # ===== Save PUBLIC KEY =====
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (Path(KEY_DIR) / "rsa_public.pem").write_bytes(public_pem)

    key_logger.info("RSA keypair generated successfully.")
    print("RSA keypair generated.")


# ============================================================
# LOAD ONLY PUBLIC KEY (NO PASSWORD REQUIRED)
# ============================================================
def load_public_key():
    """
    Load RSA public key from PEM file (no password).
    """
    try:
        public_pem = (Path(KEY_DIR) / "rsa_public.pem").read_bytes()
        return serialization.load_pem_public_key(public_pem)
    except Exception as e:
        error_logger.error(f"Failed loading public key: {e}")
        raise ValueError("Failed to load RSA public key.")


# ============================================================
# LOAD PRIVATE KEY (PASSWORD REQUIRED)
# ============================================================
def load_private_key(password: str):
    """
    Load RSA private key (must be decrypted with password).
    """
    try:
        private_pem = (Path(KEY_DIR) / "rsa_private.pem").read_bytes()
        return serialization.load_pem_private_key(
            private_pem,
            password=password.encode(),
        )
    except Exception as e:
        error_logger.error(f"Failed loading private key: {e}")
        raise ValueError("Incorrect password or corrupted private key file.")


# ============================================================
# LOAD BOTH PRIVATE & PUBLIC KEYS
# ============================================================
def load_rsa_keys(password: str):
    private = load_private_key(password)
    public = load_public_key()
    return private, public