from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.settings import KEY_DIR
from app.core.logging_config import key_logger


# ============================================================
# INTERNAL HELPERS
# ============================================================
def _rsa_base_dir() -> Path:
    return Path(KEY_DIR) / "rsa"


def _rsa_version_dir(version: str) -> Path:
    return _rsa_base_dir() / version


def _current_file() -> Path:
    return _rsa_base_dir() / "current"


# ============================================================
# CURRENT VERSION MANAGEMENT
# ============================================================
def get_current_rsa_version() -> str:
    """
    Return current active RSA key version (v1, v2, ...)
    """
    current = _current_file()
    if not current.exists():
        raise RuntimeError("RSA current version file not found")
    return current.read_text().strip()


def set_current_rsa_version(version: str):
    """
    Set current active RSA key version
    """
    _rsa_base_dir().mkdir(parents=True, exist_ok=True)
    _current_file().write_text(version)
    key_logger.info(f"RSA current version set to {version}")


# ============================================================
# KEY GENERATION
# ============================================================
def generate_rsa_keys(password: str, version: str, key_size: int = 4096):
    """
    Generate RSA keypair for a given version.
    Private key is encrypted using provided password.
    """
    if not password or len(password) < 6:
        raise ValueError("RSA private key password must be >= 6 characters")

    rsa_dir = _rsa_version_dir(version)
    rsa_dir.mkdir(parents=True, exist_ok=True)

    key_logger.info(f"Generating RSA keypair version {version}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    # private key (password protected)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    (rsa_dir / "private.pem").write_bytes(private_pem)

    # public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (rsa_dir / "public.pem").write_bytes(public_pem)

    key_logger.info(f"RSA keypair {version} generated")


# ============================================================
# LOAD KEYS BY VERSION
# ============================================================
def load_private_key_by_version(version: str, password: str):
    """
    Load RSA private key for specific version (password required)
    """
    key_path = _rsa_version_dir(version) / "private.pem"
    if not key_path.exists():
        raise FileNotFoundError(f"RSA private key not found for version {version}")

    try:
        return serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=password.encode(),
        )
    except ValueError:
        raise ValueError("Incorrect RSA private key password")


def load_public_key_by_version(version: str):
    """
    Load RSA public key for specific version (no password)
    """
    key_path = _rsa_version_dir(version) / "public.pem"
    if not key_path.exists():
        raise FileNotFoundError(f"RSA public key not found for version {version}")

    return serialization.load_pem_public_key(key_path.read_bytes())


# ============================================================
# CONVENIENCE HELPERS
# ============================================================
def load_current_public_key():
    """
    Load public key of current RSA version
    """
    return load_public_key_by_version(get_current_rsa_version())


def load_current_private_key(password: str):
    """
    Load private key of current RSA version
    """
    return load_private_key_by_version(get_current_rsa_version(), password)
