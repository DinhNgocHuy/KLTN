import boto3
from config import get_bucket_name

def upload_file_to_s3(file_path, s3_key):
    bucket_name = get_bucket_name()
    if not bucket_name:
        raise Exception("Bucket name undefined!")

    s3 = boto3.client("s3")
    print(f"Uploading {file_path} to s3://{bucket_name}/{s3_key}")

    s3.upload_file(file_path, bucket_name, s3_key)

    print("Upload successful!")

if __name__ == "__main__":
    upload_file_to_s3("../data/original/quocphong_ss2.docx", "backup/sample1.docx.enc")
