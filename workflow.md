┌──────────────────┐
│  Người dùng      │
│ (Upload dữ liệu) │
└───────┬──────────┘
        │
        ▼
┌────────────────────────┐
│  Encryption Module     │
│  - Sinh key AES        │
│  - Mã hóa file gốc     │
│  - Lưu key (RSA/AES)   │
└─────────┬──────────────┘
          │
          ▼
┌───────────────────────────────────┐
│  S3 Upload Module                 │
│  - Đọc bucket từ Terraform output │
│  - Upload file .enc lên AWS S3    │
└─────────┬─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│  AWS S3 Storage (Cloud) │
│  - Lưu trữ file mã hóa  │
│  - Có versioning, policy│
└─────────┬───────────── ─┘
          │
          ▼
┌────────────────────────┐
│  Download Module       │
│  - Kiểm tra toàn vẹn   │
│  - Tải file .enc từ S3 │
└─────────┬──────────────┘
          │
          ▼
┌────────────────────────┐
│  Decryption Module     │
│  - Giải mã bằng AES key│
│  - Phục hồi file gốc   │
└─────────┬──────────────┘
          │
          ▼
┌────────────────────────────────┐
│  Verify Integrity              │
│  - Hash SHA256 gốc vs restored │
│  - Kết luận toàn vẹn dữ liệu   │
└────────────────────────────────┘