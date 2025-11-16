##################################################
#region AWS S3 Bucket
##################################################
data "aws_canonical_user_id" "default" {}

# Create an S3 bucket
resource "aws_s3_bucket" "main" {
  #checkov:skip=CKV_AWS_18: "Ensure the S3 bucket has access logging enabled"
  #checkov:skip=CKV_AWS_19: "Ensure all data stored in the S3 bucket is securely encrypted at rest"
  #checkov:skip=CKV_AWS_21: "Ensure all data stored in the S3 bucket have versioning enabled"
  #checkov:skip=CKV_AWS_144: "Ensure that S3 bucket has cross-region replication enabled"
  #checkov:skip=CKV_AWS_145: "Ensure that S3 buckets are encrypted with KMS by default"
  #checkov:skip=CKV2_AWS_6: "Ensure that S3 bucket has a Public Access block"
  #checkov:skip=CKV2_AWS_61: "Ensure that an S3 bucket has a lifecycle configuration"
  #checkov:skip=CKV2_AWS_62: "Ensure S3 buckets should have event notifications enabled"
  bucket              = var.bucket
  bucket_prefix       = var.bucket_prefix
  force_destroy       = var.force_destroy
  object_lock_enabled = var.object_lock_enabled
  tags                = var.tags
}

# Enable versioning to keep multiple variants of an object in the same bucket
resource "aws_s3_bucket_versioning" "this" {
  for_each = var.versioning

  bucket                = aws_s3_bucket.main.id
  expected_bucket_owner = each.value.expected_bucket_owner
  mfa                   = each.value.mfa

  dynamic "versioning_configuration" {
    for_each = try([each.value.versioning_configuration], [])

    content {
      status     = versioning_configuration.value.status
      mfa_delete = versioning_configuration.value.mfa_delete
    }
  }
}

# Grant bucket policy to allows you to manage access to a specific S3 storage resource
resource "aws_s3_bucket_policy" "this" {
  for_each = var.policies

  bucket = aws_s3_bucket.main.id
  policy = each.value.policy
}

# Create ownership controls
resource "aws_s3_bucket_ownership_controls" "this" {
  #checkov:skip=CKV2_AWS_65: "Ensure access control lists for S3 buckets are disabled"

  for_each = var.ownership_controls

  bucket = aws_s3_bucket.main.id

  dynamic "rule" {
    for_each = try([each.value.rule], [])

    content {
      object_ownership = try(rule.value.object_ownership, "BucketOwnerPreferred")
    }
  }

  depends_on = [
    aws_s3_bucket.main,
    aws_s3_bucket_policy.this,
    aws_s3_bucket_public_access_block.this
  ]
}

# Create ACL
resource "aws_s3_bucket_acl" "this" {
  for_each              = var.acls
  bucket                = aws_s3_bucket.main.id
  expected_bucket_owner = each.value.expected_bucket_owner
  # acl                   = length(each.value.access_control_policy.grant) > 0 ? null : each.value.acl
  acl = try(each.value.acl, null)
  dynamic "access_control_policy" {
    # for_each = try([each.value.access_control_policy], [])
    for_each = try(each.value.acl, null) == null && try(length(each.value.access_control_policy.grant), 0) > 0 ? [each.value.access_control_policy] : []
    content {
      dynamic "grant" {
        for_each = access_control_policy.value.grant
        content {
          permission = grant.value.permission
          dynamic "grantee" {
            for_each = try([grant.value.grantee], [])
            content {
              type          = grantee.value.type
              id            = grantee.value.id
              uri           = grantee.value.uri
              email_address = grantee.value.email_address
            }
          }
        }
      }
      dynamic "owner" {
        for_each = try([access_control_policy.value.owner], [])
        content {
          id           = coalesce(owner.value.id, data.aws_canonical_user_id.default.id)
          display_name = owner.value.display_name
        }
      }
    }
  }
  # This is to prevent "AccessControlListNotSupported: The bucket does not allow ACLs"
  depends_on = [aws_s3_bucket_ownership_controls.this]
}

# Create static website configuration
resource "aws_s3_bucket_website_configuration" "this" {
  for_each = var.website_configuration

  bucket                = aws_s3_bucket.main.id
  expected_bucket_owner = each.value.expected_bucket_owner

  dynamic "index_document" {
    for_each = try([var.website_configuration.index_document], [])

    content {
      suffix = index_document.value
    }
  }

  dynamic "error_document" {
    for_each = try([var.website_configuration.error_document], [])

    content {
      key = error_document.value
    }
  }

  dynamic "redirect_all_requests_to" {
    for_each = try([var.website_configuration.redirect_all_requests_to], [])

    content {
      host_name = redirect_all_requests_to.value.host_name
      protocol  = redirect_all_requests_to.value.protocol
    }
  }

  dynamic "routing_rule" {
    for_each = try([var.website_configuration.routing_rule], [])

    content {
      dynamic "condition" {
        for_each = try([routing_rule.value.condition], [])

        content {
          key_prefix_equals               = condition.value.key_prefix_equals
          http_error_code_returned_equals = condition.value.http_error_code_returned_equals
        }
      }

      dynamic "redirect" {
        for_each = try([routing_rule.value.redirect], [])

        content {
          host_name               = redirect.value.host_name
          http_redirect_code      = redirect.value.http_redirect_code
          protocol                = redirect.value.protocol
          replace_key_prefix_with = redirect.value.replace_key_prefix_with
          replace_key_with        = redirect.value.replace_key_with
        }
      }
    }
  }
}

# Configure server side encryption 
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = var.encryption_configuration

  bucket                = aws_s3_bucket.main.id
  expected_bucket_owner = each.value.expected_bucket_owner

  dynamic "rule" {
    for_each = try([each.value.rule], [])

    content {
      dynamic "apply_server_side_encryption_by_default" {
        for_each = try([rule.value.apply_server_side_encryption_by_default], [])

        content {
          sse_algorithm     = apply_server_side_encryption_by_default.value.sse_algorithm
          kms_master_key_id = apply_server_side_encryption_by_default.value.kms_master_key_id
        }
      }

      bucket_key_enabled = rule.value.bucket_key_enabled
    }
  }
}

# Create a resource to consists of a set of rules with predefined actions that you want Amazon S3 to perform on objects during their lifetime
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  #checkov:skip=CKV_AWS_300: "Ensure S3 lifecycle configuration sets period for aborting failed uploads"

  for_each = var.lifecycle_configuration

  bucket                                 = aws_s3_bucket.main.id
  expected_bucket_owner                  = each.value.expected_bucket_owner
  transition_default_minimum_object_size = each.value.transition_default_minimum_object_size

  dynamic "rule" {
    for_each = each.value.rule

    content {
      id     = rule.value.id
      status = rule.value.status

      dynamic "abort_incomplete_multipart_upload" {
        for_each = rule.value["abort_incomplete_multipart_upload"]

        content {
          days_after_initiation = abort_incomplete_multipart_upload.value.days_after_initiation
        }
      }

      dynamic "expiration" {
        for_each = try([rule.value.expiration], [])

        content {
          date                         = expiration.value.date
          days                         = expiration.value.days
          expired_object_delete_marker = expiration.value.expired_object_delete_marker
        }
      }

      dynamic "filter" {
        for_each = merge(rule.value.filter)

        content {
          dynamic "and" {
            for_each = filter.value.and

            content {
              object_size_greater_than = and.value.object_size_greater_than
              object_size_less_than    = and.value.object_size_less_than
              prefix                   = and.value.prefix
            }
          }

          object_size_greater_than = filter.value.object_size_greater_than
          object_size_less_than    = filter.value.object_size_less_than
          prefix                   = filter.value.prefix
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value["noncurrent_version_expiration"]

        content {
          newer_noncurrent_versions = noncurrent_version_expiration.value.newer_noncurrent_versions
          noncurrent_days           = noncurrent_version_expiration.value.noncurrent_days
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = length(rule.value.noncurrent_version_transition) > 0 ? rule.value.noncurrent_version_transition : {}

        content {
          newer_noncurrent_versions = noncurrent_version_transition.value.newer_noncurrent_versions
          noncurrent_days           = noncurrent_version_transition.value.noncurrent_days
          storage_class             = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "transition" {
        for_each = length(rule.value.transition) > 0 ? rule.value.transition : {}

        content {
          date          = transition.value.date
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }
    }
  }
}

# Create a resource to provide controls across an entire AWS Account or at the individual S3 bucket level to ensure that objects never have public access, now and in the future
resource "aws_s3_bucket_public_access_block" "this" {
  #checkov:skip=CKV_AWS_53: "Ensure S3 bucket has ignore_public_acls enabled"
  #checkov:skip=CKV_AWS_54: "Ensure S3 bucket has block_public_policy enabled"
  #checkov:skip=CKV_AWS_55: "Ensure S3 bucket has ignore_public_acls enabled"
  #checkov:skip=CKV_AWS_56: "Ensure S3 bucket has restrict_public_buckets enabled"

  for_each = var.public_access_block

  bucket                  = aws_s3_bucket.main.id
  restrict_public_buckets = try(each.value.restrict_public_buckets, true)
  block_public_acls       = try(each.value.block_public_acls, true)
  block_public_policy     = try(each.value.block_public_policy, true)
  ignore_public_acls      = try(each.value.ignore_public_acls, true)
}

# Create a resource to provide detailed records for the requests that are made to an Amazon S3 bucket.
resource "aws_s3_bucket_logging" "this" {
  for_each = var.logging

  bucket                = aws_s3_bucket.main.id
  expected_bucket_owner = try(each.value.expected_bucket_owner, null)

  target_bucket = each.value.target_bucket
  target_prefix = try(each.value.target_prefix, null)

  dynamic "target_grant" {
    for_each = each.value.target_grant
    content {
      permission = target_grant.value.permission

      dynamic "grantee" {
        for_each = target_grant.value.grantee

        content {
          type          = grantee.value.type
          id            = grantee.value.id
          uri           = grantee.value.uri
          email_address = grantee.value.email_address
        }
      }
    }
  }

  dynamic "target_object_key_format" {
    for_each = each.value.target_object_key_format
    content {
      dynamic "partitioned_prefix" {
        for_each = target_object_key_format.value.partitioned_prefix
        content {
          partition_date_source = partitioned_prefix.value.partition_date_source
        }
      }
      dynamic "simple_prefix" {
        for_each = target_object_key_format.value.simple_prefix != null ? [target_object_key_format.value.simple_prefix] : []
        content {}
      }
    }
  }
}

# Create a resource to support two-way replication between two or more buckets in the same or different AWS Regions
resource "aws_s3_bucket_replication_configuration" "this" {
  for_each = var.replication_configuration

  bucket = aws_s3_bucket.main.id
  role   = each.value.role
  token  = try(each.value.token, null)

  dynamic "rule" {
    for_each = try([each.value.rule], [])

    content {
      id       = rule.value.id
      priority = rule.value.priority
      status   = rule.value.status

      dynamic "delete_marker_replication" {
        for_each = try([rule.value.delete_marker_replication], [])

        content {
          status = delete_marker_replication.value.status
        }
      }

      dynamic "existing_object_replication" {
        for_each = try([rule.value.existing_object_replication], [])

        content {
          status = existing_object_replication.value.status
        }
      }

      dynamic "filter" {
        for_each = try([rule.value.filter], [])

        content {
          prefix = filter.value.prefix

          dynamic "and" {
            for_each = try([filter.value.and], [])

            content {
              prefix = and.value.prefix
            }
          }
        }
      }

      dynamic "source_selection_criteria" {
        for_each = try([rule.value.source_selection_criteria], [])

        content {
          dynamic "replica_modifications" {
            for_each = try([source_selection_criteria.value.replica_modifications], [])

            content {
              status = replica_modifications.value.status
            }
          }

          dynamic "sse_kms_encrypted_objects" {
            for_each = try([source_selection_criteria.value.sse_kms_encrypted_objects], [])

            content {
              status = sse_kms_encrypted_objects.value.status
            }
          }
        }
      }

      dynamic "destination" {
        for_each = try([rule.value.destination], [])

        content {
          account       = destination.value.account
          bucket        = destination.value.bucket
          storage_class = destination.value.storage_class

          dynamic "access_control_translation" {
            for_each = try([destination.value.access_control_translation], [])

            content {
              owner = access_control_translation.value.owner
            }
          }

          dynamic "encryption_configuration" {
            for_each = try([destination.value.encryption_configuration], [])

            content {
              replica_kms_key_id = encryption_configuration.value.replica_kms_key_id
            }
          }

          dynamic "metrics" {
            for_each = try([destination.value.metrics], [])

            content {
              dynamic "event_threshold" {
                for_each = try([metrics.value.event_threshold], [])

                content {
                  minutes = event_threshold.value.minutes
                }
              }
              status = metrics.value.status
            }
          }

          dynamic "replication_time" {
            for_each = try([destination.value.replication_time], [])

            content {
              status = replication_time.value.status

              dynamic "time" {
                for_each = [replication_time.value.time]

                content {
                  minutes = time.value.minutes
                }
              }
            }
          }
        }
      }
    }
  }
}


resource "aws_s3_bucket_cors_configuration" "this" {
  for_each = var.buckets_cors

  bucket = aws_s3_bucket.main.id

  dynamic "cors_rule" {
    for_each = each.value.cors_rules

    content {
      allowed_headers = try(cors_rule.value.allowed_headers, null)
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      expose_headers  = try(cors_rule.value.expose_headers, null)
      max_age_seconds = try(cors_rule.value.max_age_seconds, null)
    }
  }

  depends_on = [aws_s3_bucket.main]
}



##################################################
#endregion
##################################################