##################################################
#region AWS S3 Bucket
##################################################
output "id" {
  description = "The S3 bucket name"
  value       = aws_s3_bucket.main.id
}

output "arn" {
  description = "The S3 bucket arn"
  value       = aws_s3_bucket.main.arn
}

output "bucket_domain_name" {
  description = "The S3 bucket domain name"
  value       = aws_s3_bucket.main.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "The S3 bucket domain name"
  value       = aws_s3_bucket.main.bucket_regional_domain_name
}

output "hosted_zone_id" {
  description = "The hosted zone ID"
  value       = aws_s3_bucket.main.hosted_zone_id
}

output "rule" {
  description = "The rule of the S3 bucket lifecycle configuration"
  sensitive   = true
  value = {
    for k, v in aws_s3_bucket_lifecycle_configuration.this : k => v.rule
  }
}

output "policy" {
  description = "The S3 bucket policy"
  sensitive   = true
  value = {
    for k, v in aws_s3_bucket_policy.this : k => v.policy
  }
}

output "region" {
  description = "The AWS region in which this bucket resides"
  value       = aws_s3_bucket.main.region
}

output "website_endpoint" {
  description = "The website endpoint of the S3 bucket"
  value = {
    for k, v in aws_s3_bucket_website_configuration.this : k => v.website_endpoint
  }
}

output "website_domain" {
  description = "The domain of the website endpoint. This is used to create Route53 alias records"
  value = {
    for k, v in aws_s3_bucket_website_configuration.this : k => v.website_domain
  }
}
##################################################
#endregion
##################################################