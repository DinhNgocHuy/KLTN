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

  lifecycle_configuration = {
    lifecycle_configuration = {
      bucket = var.bucket

      transition_default_minimum_object_size = "varies_by_storage_class"
      rule = [{
        id     = "Transition_Rules"
        status = "Enabled"

        transition = {
          glacier_transition = {
            days          = 30
            storage_class = "GLACIER"
          }
        }
        filter = {
          root_prefix = {
            prefix = ""
          }
        }
      }]
    }
  }
}