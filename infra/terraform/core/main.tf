locals {
  bucket = var.bucket
}
module "aws_s3_bucket" {
  source = "../modules/aws-s3-bucket"
  bucket = local.bucket
  versioning = {
    versioning = {
        bucket = local.bucket
        versioning_configuration = {
            status = "Enabled"
        }
    }
  }

  public_access_block = {
    public_access_block = {
        bucket = local.bucket
        block_public_acls       = true
        block_public_policy     = true
        ignore_public_acls      = true
        restrict_public_buckets = true
    }
  }
    
}