import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = "../keys"

def generate_rsa_keys():
    """
    Generate RSA private/public keypair and save to KEY_DIR.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    os.makedirs(KEY_DIR, exist_ok=True)

    # Save private key
    with open(f"{KEY_DIR}/rsa_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with open(f"{KEY_DIR}/rsa_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("✔ RSA keypair generated.")


def load_rsa_keys():
    """
    Load RSA private & public keys from KEY_DIR.
    """
    with open(f"{KEY_DIR}/rsa_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), None)

    with open(f"{KEY_DIR}/rsa_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key
