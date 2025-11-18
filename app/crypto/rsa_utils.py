import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from app.settings import KEY_DIR
from app.logging_config import key_logger, error_logger


# ============================================================
# 1) GENERATE RSA KEYPAIR (PRIVATE KEY PROTECTED BY PASSWORD)
# ============================================================
def generate_rsa_keys(password: str):
    """
    Generate RSA private/public keys.
    Private key is encrypted using the provided password.
    """

    key_logger.info("Generating RSA keypair (password protected)...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,   # mạnh hơn 2048
    )
    public_key = private_key.public_key()

    Path(KEY_DIR).mkdir(parents=True, exist_ok=True)

    password_bytes = password.encode()

    # --- Save encrypted private key ---
    try:
        with open(f"{KEY_DIR}/rsa_private.pem", "wb") as f:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,  # chuẩn nhất 2025
                encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
            )
            f.write(pem)
    except Exception as e:
        error_logger.error(f"Failed to write encrypted private key: {e}")
        raise

    # --- Save public key ---
    try:
        with open(f"{KEY_DIR}/rsa_public.pem", "wb") as f:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            f.write(pem)
    except Exception as e:
        error_logger.error(f"Failed to write public key: {e}")
        raise

    key_logger.info("RSA keypair generated successfully.")
    print("✔ RSA keypair generated (private key is password-protected)")


# ============================================================
# 2) LOAD PRIVATE & PUBLIC KEY (REQUIRES PASSWORD)
# ============================================================
def load_rsa_keys(password: str):
    """
    Load RSA private & public keys.
    Private key requires password to decrypt.
    """

    # --- Load encrypted private key ---
    try:
        with open(f"{KEY_DIR}/rsa_private.pem", "rb") as f:
            encrypted_pem = f.read()

        private_key = serialization.load_pem_private_key(
            encrypted_pem,
            password=password.encode(),   # must match password used during generate
        )
    except Exception as e:
        error_logger.error(f"Failed to load private key: {e}")
        raise ValueError("❌ Incorrect password or corrupted private key file.")

    # --- Load public key ---
    try:
        with open(f"{KEY_DIR}/rsa_public.pem", "rb") as f:
            public_pem = f.read()

        public_key = serialization.load_pem_public_key(public_pem)
    except Exception as e:
        error_logger.error(f"Failed to load public key: {e}")
        raise

    return private_key, public_key