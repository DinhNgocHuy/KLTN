# =========================
# Global configuration for Encryption/Decryption
# =========================

KEY_DIR = "../keys"
DATA_DIR = "../data"

# AES-GCM parameters
AES_KEY_SIZE = 32         # 256-bit AES
NONCE_SIZE = 12           # 96-bit nonce (recommended for GCM)
TAG_SIZE = 16             # 128-bit GCM tag
CHUNK_SIZE = 1024 * 1024  # 1 MB per chunk (streaming)
