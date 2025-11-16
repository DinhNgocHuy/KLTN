import json
import subprocess

def get_bucket_name():
    """
    Get output bucket_name from Terraform (in the terraform/ directory)
    """
    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd="../terraform/core",
            capture_output=True,
            text=True,
            check=True
        )
        outputs = json.loads(result.stdout)
        return outputs["id"]["value"]
    except Exception as e:
        print("Cannot get Terraform output:", e)
        return None

# Example test:
if __name__ == "__main__":
    print("S3 Bucket:", get_bucket_name())
