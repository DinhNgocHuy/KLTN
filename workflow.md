┌──────────────────────────┐
│        User Input        │
│   (Select source file)   │
└─────────────┬────────────┘
              │
              ▼
┌────────────────────────────────┐
│       Encryption Module        │
│  - Generate AES-256 key        │
│  - Encrypt original file       │
│  - Compute SHA-256 metadata    │
│  - RSA-encrypt AES key         │
└─────────────┬──────────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│      S3 Bucket Validation Module             │
│  - Read bucket name from Terraform output    │
│  - Check if bucket exists:                   │
│        • Exists  → continue                  │
│        • Missing → auto-create bucket        │
└─────────────┬────────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│            S3 Upload Module                │
│  - Upload *.enc, *.key.enc, metadata.json  │
│  - Use multipart upload                    │
│  - Ensure versioning + bucket policy        │
└─────────────┬──────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│           AWS S3 Cloud Storage             │
│  - Stores encrypted objects                │
│  - Versioning, lifecycle, policy controls  │
└─────────────┬──────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│   Pre-Download Integrity & Metadata Check  │
│  - Check metadata.json exists on S3        │
│  - Validate object size, last-modified      │
│  - Optional: Compare ETag vs expected hash  │
│  - Decision:                                │
│        • If metadata missing/invalid → STOP │
│        • If OK → allow download             │
└─────────────┬──────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│              Download Module               │
│  - Download encrypted file(s)              │
│  - Download AES key + metadata             │
└─────────────┬──────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│     Post-Download Integrity Verification   │
│  - Recompute SHA-256 of downloaded file    │
│  - Compare with metadata.json hash         │
│  - If mismatch → STOP (possible tampering) │
└─────────────┬──────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│              Decryption Module              │
│  - RSA-decrypt AES key                      │
│  - AES-GCM decrypt encrypted file           │
│  - Restore original plaintext               │
└─────────────┬──────────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────┐
│        Final End-to-End Verification        │
│  - SHA256(original) vs SHA256(restored)    │
│  - Guarantee full data integrity            │
└────────────────────────────────────────────┘
