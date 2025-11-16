##################################################
#region AWS S3 Bucket
##################################################
output "id" {
  description = "The S3 bucket name"
  value       = module.aws_s3_bucket.id
}

output "arn" {
  description = "The S3 bucket arn"
  value       = module.aws_s3_bucket.arn
}

output "bucket_domain_name" {
  description = "The S3 bucket domain name"
  value       = module.aws_s3_bucket.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "The S3 bucket domain name"
  value       = module.aws_s3_bucket.bucket_regional_domain_name
}

output "hosted_zone_id" {
  description = "The hosted zone ID"
  value       = module.aws_s3_bucket.hosted_zone_id
}

# output "rule" {
#   description = "The rule of the S3 bucket lifecycle configuration"
#   sensitive   = true
#   value = {
#     for k, v in aws_s3_bucket_lifecycle_configuration.this : k => v.rule
#   }
# }

# output "policy" {
#   description = "The S3 bucket policy"
#   sensitive   = true
#   value = {
#     for k, v in aws_s3_bucket_policy.this : k => v.policy
#   }
# }


##################################################
#endregion
##################################################