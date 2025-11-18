import os
import time
import glob
import hashlib
import boto3

from app.logging_config import s3_upload_logger, error_logger
from app.settings import get_bucket_name
from app.settings import DATA_DIR

# ============================================================
# SHA256 CHECKSUM
# ============================================================
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

# ============================================================
# GET REMOTE SHA256
# ============================================================
def s3_get_remote_sha(bucket, key):
    s3 = boto3.client("s3")
    try:
        obj = s3.head_object(Bucket=bucket, Key=key)
        return obj.get("Metadata", {}).get("sha256", None)
    except:
        return None

# ============================================================
# MULTIPART UPLOAD FOR LARGE FILES (>5GB)
# ============================================================
def multipart_upload(local_path, bucket, key, metadata):
    s3 = boto3.client("s3")
    mp = s3.create_multipart_upload(Bucket=bucket, Key=key, Metadata=metadata)
    upload_id = mp["UploadId"]
    parts = []

    part_number = 1
    with open(local_path, "rb") as f:
        while True:
            data = f.read(5 * 1024 * 1024)  # 5MB chunk
            if not data:
                break
            resp = s3.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=part_number,
                Body=data
            )
            parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
            part_number += 1

    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": parts},
    )


# ============================================================
# UPLOAD WITH INCREMENTAL CHECK
# ============================================================
def upload_file_to_s3(local_path, s3_key):
    bucket = get_bucket_name()
    if not bucket:
        raise Exception("Bucket name undefined!")

    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    local_sha = sha256_file(local_path)
    remote_sha = s3_get_remote_sha(bucket, s3_key)

    # Skip identical
    if remote_sha == local_sha:
        print(f"⏩ Skipped (unchanged): {local_path}")
        s3_upload_logger.info(f"SKIPPED | file={local_path} | reason=SHA256_match")
        return

    filesize = os.path.getsize(local_path)
    metadata = {
        "encrypted": "true",
        "sha256": local_sha,
        "upload_time": str(int(time.time()))
    }

    print(f"Uploading {local_path} → s3://{bucket}/{s3_key}")
    start = time.perf_counter()

    try:
        # Small file → use put_object
        if filesize < 5 * 1024 * 1024 * 1024:  # <5GB
            s3 = boto3.client("s3")
            with open(local_path, "rb") as f:
                s3.put_object(
                    Bucket=bucket,
                    Key=s3_key,
                    Body=f,
                    Metadata=metadata
                )
        else:
            # Large file → multipart upload
            multipart_upload(local_path, bucket, s3_key, metadata)

        elapsed = time.perf_counter() - start
        print(f"✔ Uploaded {local_path} in {elapsed:.2f}s")
        s3_upload_logger.info(
            f"UPLOAD SUCCESS | file={local_path} | s3={s3_key} | sha256={local_sha} | time={elapsed:.2f}s"
        )

    except Exception as e:
        elapsed = time.perf_counter() - start
        print(f"Upload failed: {local_path} → {str(e)}")
        error_logger.error(
            f"UPLOAD FAIL | file={local_path} | s3={s3_key} | error={str(e)} | time={elapsed:.2f}s"
        )
        raise

# ============================================================
# UPLOAD ALL
# ============================================================
def upload_all_encrypted():
    bucket = get_bucket_name()
    if not bucket:
        raise Exception("Bucket name undefined!")

    encrypted_folder = f"{DATA_DIR}/encrypted"
    print(f"Scanning folder: {encrypted_folder}")

    files = glob.glob(os.path.join(encrypted_folder, "*.*"))

    upload_files = [
        f for f in files
        if f.endswith(".enc") or f.endswith(".key.enc") or f.endswith(".metadata.json")
    ]

    print(f"Found {len(upload_files)} encrypted files to upload.")

    for local_path in upload_files:
        name = os.path.basename(local_path)

        if name.endswith(".enc") and not name.endswith(".key.enc"):
            s3_key = f"encrypted/{name}"
        elif name.endswith(".key.enc"):
            s3_key = f"keys/{name}"
        elif name.endswith(".metadata.json"):
            s3_key = f"metadata/{name}"
        else:
            continue

        upload_file_to_s3(local_path, s3_key)

    print("✔ Completed incremental upload to S3.")

# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys

    args = sys.argv[1:] if len(sys.argv) > 1 else []

    if "--all" in args:
        upload_all_encrypted()
    else:
        print("Usage: python s3_upload.py --all")
