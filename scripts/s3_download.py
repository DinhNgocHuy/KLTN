import boto3
from config import get_bucket_name

def download_from_s3(s3_key, download_path):
    bucket_name = get_bucket_name()
    s3 = boto3.client("s3")
    print(f"⬇Downloading s3://{bucket_name}/{s3_key} → {download_path}")
    s3.download_file(bucket_name, s3_key, download_path)
    print("Download successful!")
