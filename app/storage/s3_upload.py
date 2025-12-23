import os
import time
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
        s3.abort_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
        )
        raise e


# ============================================================
# SINGLE FILE UPLOAD (CORE)
# ============================================================

def upload_file_to_s3(local_path, s3_key):
    bucket = get_bucket_name()
    if not bucket:
        raise ValueError("Bucket name undefined.")

    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local file not found: {local_path}")

    local_sha = sha256_file(local_path)
    remote_sha = s3_get_remote_sha(bucket, s3_key)

    # Skip identical file
    if remote_sha == local_sha:
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

    start = time.perf_counter()

    try:
        if filesize < 5 * 1024 * 1024 * 1024:
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
        s3_upload_logger.info(
            f"UPLOAD OK | file={local_path} | s3={s3_key} | sha256={local_sha} | time={elapsed:.2f}s"
        )

    except Exception as e:
        elapsed = time.perf_counter() - start
        error_logger.error(
            f"UPLOAD FAIL | file={local_path} | s3_key={s3_key} | err={str(e)} | time={elapsed:.2f}s"
        )
        raise


# ============================================================
# UPLOAD ALL ENCRYPTED ARTIFACTS (GUI / CLI)
# ============================================================

def upload_all_encrypted():
    base_dir = Path(DATA_DIR) / "encrypted"

    files = [
        f for f in base_dir.glob("*")
        if f.suffix in [".enc", ".json"] or f.name.endswith(".key.enc")
    ]

    for path in files:
        name = path.name

        if name.endswith(".enc") and not name.endswith(".key.enc"):
            s3_key = f"encrypted/{name}"
        elif name.endswith(".key.enc"):
            s3_key = f"keys/{name}"
        elif name.endswith(".metadata.json"):
            s3_key = f"metadata/{name}"
        else:
            continue

        upload_file_to_s3(str(path), s3_key)


# ============================================================
# UPLOAD WHOLE FOLDER (SCHEDULER API)
# ============================================================

def upload_folder(folder_path):
    """
    Wrapper for scheduler.
    Upload all encrypted artifacts inside given folder.
    """
    folder_path = Path(folder_path)

    if not folder_path.exists():
        error_logger.error(f"Upload folder not found: {folder_path}")
        return

    for path in folder_path.glob("*"):
        name = path.name

        if name.endswith(".enc") and not name.endswith(".key.enc"):
            s3_key = f"encrypted/{name}"
        elif name.endswith(".key.enc"):
            s3_key = f"keys/{name}"
        elif name.endswith(".metadata.json"):
            s3_key = f"metadata/{name}"
        else:
            continue

        upload_file_to_s3(str(path), s3_key)


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    if "--all" in sys.argv:
        upload_all_encrypted()
    else:
        print("Usage: python s3_upload.py --all")
