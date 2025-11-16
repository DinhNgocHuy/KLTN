import os
import boto3

from encryption_config import DATA_DIR
from config import get_bucket_name

# ============================================================
# GLOBAL
# ============================================================
S3_BUCKET = get_bucket_name()
s3 = boto3.client("s3")

ENCRYPTED_LOCAL_FOLDER = f"{DATA_DIR}/encrypted"


# ============================================================
# 1) DOWNLOAD 1 FILE PAIR (.enc + .key.enc)
# ============================================================
def download_file_pair(filename, target_folder=ENCRYPTED_LOCAL_FOLDER):
    """
    Tải file <filename>.enc và <filename>.key.enc về thư mục local.
    Ví dụ filename = "quocphong_ss2.docx"
    """

    os.makedirs(target_folder, exist_ok=True)

    enc_s3_key = f"encrypted/{filename}.enc"
    key_s3_key = f"keys/{filename}.key.enc"

    enc_local = os.path.join(target_folder, f"{filename}.enc")
    key_local = os.path.join(target_folder, f"{filename}.key.enc")

    print(f"\n=== DOWNLOAD: {filename} ===")

    # -------- DOWNLOAD .enc --------
    try:
        print(f"[S3] Fetching {enc_s3_key} → {enc_local}")
        s3.download_file(S3_BUCKET, enc_s3_key, enc_local)
        print("✔ Downloaded .enc")
    except Exception as e:
        print(f"❌ Failed to download encrypted file: {enc_s3_key} — {e}")
        return None, None

    # -------- DOWNLOAD .key.enc --------
    try:
        print(f"[S3] Fetching {key_s3_key} → {key_local}")
        s3.download_file(S3_BUCKET, key_s3_key, key_local)
        print("✔ Downloaded key file")
    except Exception as e:
        print(f"❌ Failed to download key file: {key_s3_key} — {e}")
        return None, None

    print("✔ DONE downloading file pair.\n")
    return enc_local, key_local



# ============================================================
# 2) DOWNLOAD ALL ENCRYPTED FILES IN S3
# ============================================================
def download_all_encrypted(target_folder=ENCRYPTED_LOCAL_FOLDER):
    """
    Tải TẤT CẢ file encrypted trong S3 về local.
    (tự động ghép key đúng file)
    """

    print(f"Listing encrypted objects from S3 bucket: {S3_BUCKET}")

    os.makedirs(target_folder, exist_ok=True)

    # GET LIST *.enc from S3
    objects = s3.list_objects_v2(
        Bucket=S3_BUCKET,
        Prefix="encrypted/"
    )

    if "Contents" not in objects:
        print("❌ No encrypted files found in S3.")
        return

    encrypted_files = [
        os.path.basename(obj["Key"]).replace(".enc", "")
        for obj in objects["Contents"]
        if obj["Key"].endswith(".enc")
    ]

    print(f"Found {len(encrypted_files)} encrypted objects in S3.\n")

    # Download each pair
    for base in encrypted_files:
        download_file_pair(base, target_folder)

    print("✔ DONE downloading ALL encrypted data from S3.\n")



# ============================================================
# 3) MAIN ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import sys

    args = sys.argv[1:]

    # Download toàn bộ encrypted folder
    if "--all" in args:
        download_all_encrypted()
        exit()

    # Download 1 file cụ thể
    if "--file" in args:
        idx = args.index("--file")
        filename = args[idx + 1]
        download_file_pair(filename)
        exit()

    # Hướng dẫn
    print("Usage:")
    print("  py s3_download.py --file <filename>")
    print("  py s3_download.py --all")
