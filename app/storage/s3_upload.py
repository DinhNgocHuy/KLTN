import os
import time
import glob
import hashlib
import boto3

from pathlib import Path
from botocore.exceptions import ClientError

from app.core.logging_config import s3_upload_logger, error_logger
from app.core.settings import get_bucket_name, DATA_DIR
from app.utils.checksum import sha256_file

# ============================================================
# GET REMOTE SHA256 FROM S3 (metadata)
# ============================================================
def s3_get_remote_sha(bucket, key):
    s3 = boto3.client("s3")
    try:
        obj = s3.head_object(Bucket=bucket, Key=key)
        return obj.get("Metadata", {}).get("sha256")
    except ClientError:
        return None


# ============================================================
# MULTIPART UPLOAD (for files > 5GB)
# ============================================================
def multipart_upload(local_path, bucket, key, metadata):
    s3 = boto3.client("s3")
    mp = s3.create_multipart_upload(Bucket=bucket, Key=key, Metadata=metadata)
    upload_id = mp["UploadId"]

    parts = []
    part_number = 1

    try:
        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(5 * 1024 * 1024)
                if not chunk:
                    break

                resp = s3.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=chunk,
                )

                parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
                part_number += 1

        s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

    except Exception as e:
        # Abort upload on failure (BEST PRACTICE)
        s3.abort_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
        )
        raise e


# ============================================================
# SINGLE OR MULTIPART UPLOAD
# ============================================================
def upload_file_to_s3(local_path, s3_key):
    bucket = get_bucket_name()
    if not bucket:
        raise ValueError("Bucket name undefined.")

    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    local_sha = sha256_file(local_path)
    remote_sha = s3_get_remote_sha(bucket, s3_key)

    # Skip identical
    if remote_sha == local_sha:
        print(f"Skipped (no change): {local_path}")
        s3_upload_logger.info(
            f"SKIPPED | file={local_path} | reason=SHA256_match"
        )
        return

    filesize = os.path.getsize(local_path)
    metadata = {
        "encrypted": "true",
        "sha256": local_sha,
        "upload_time": str(int(time.time())),
    }

    print(f"Uploading {local_path} → s3://{bucket}/{s3_key}")
    start = time.perf_counter()

    try:
        if filesize < 5 * 1024 * 1024 * 1024:  # <5GB
            s3 = boto3.client("s3")
            with open(local_path, "rb") as f:
                s3.put_object(
                    Bucket=bucket,
                    Key=s3_key,
                    Body=f,
                    Metadata=metadata,
                )
        else:
            multipart_upload(local_path, bucket, s3_key, metadata)

        elapsed = time.perf_counter() - start
        print(f"Uploaded {local_path} in {elapsed:.2f}s")

        s3_upload_logger.info(
            f"UPLOAD SUCCESS | file={local_path} | s3={s3_key} | sha256={local_sha} | time={elapsed:.2f}s"
        )

    except Exception as e:
        elapsed = time.perf_counter() - start
        print(f"Upload failed: {local_path} → {str(e)}")

        error_logger.error(
            f"UPLOAD FAIL | file={local_path} | s3_key={s3_key} | err={str(e)} | time={elapsed:.2f}s"
        )
        raise


# ============================================================
# SCAN & UPLOAD ALL ENCRYPTED ARTIFACTS
# ============================================================
def upload_all_encrypted():
    bucket = get_bucket_name()
    if not bucket:
        raise ValueError("Bucket name undefined.")

    base_dir = Path(DATA_DIR) / "encrypted"
    print(f"Scanning folder: {base_dir}")

    files = list(base_dir.glob("*"))

    upload_files = [
        f for f in files
        if f.suffix in [".enc", ".json"] or f.name.endswith(".key.enc")
    ]

    print(f"Found {len(upload_files)} encrypted files to upload.")

    for path in upload_files:
        name = path.name

        # classify S3 path
        if name.endswith(".enc") and not name.endswith(".key.enc"):
            s3_key = f"encrypted/{name}"
        elif name.endswith(".key.enc"):
            s3_key = f"keys/{name}"
        elif name.endswith(".metadata.json"):
            s3_key = f"metadata/{name}"
        else:
            continue

        upload_file_to_s3(str(path), s3_key)

    print("Completed incremental upload to S3.")


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys
    if "--all" in sys.argv:
        upload_all_encrypted()
    else:
        print("Usage: python s3_upload.py --all")
