##################################################
#region AWS S3 Bucket
##################################################

variable "bucket" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "bucket_prefix" {
  description = "Prefix for the bucket name"
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "Destroy bucket even if it contains objects"
  type        = bool
  default     = false
}

variable "object_lock_enabled" {
  description = "Enable object lock"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags for the S3 bucket"
  type        = map(string)
  default     = {}
}

variable "policies" {
  description = "The S3 bucket policy"
  type = map(object({
    policy = string
  }))
  default = {}
}

variable "ownership_controls" {
  description = "The S3 bucket ownership controls"
  type = map(object({
    rule = object({
      object_ownership = string
    })
  }))
  default = {}
}

variable "logging" {
  description = "The S3 bucket logging configuration"
  type = map(object({
    expected_bucket_owner = optional(string)
    target_bucket         = optional(string)
    target_prefix         = optional(string)
    target_grant = optional(map(object({
      permission = string
      grantee = list(object({
        type          = string
        id            = optional(string)
        uri           = optional(string)
        display_name  = optional(string)
        email_address = optional(string)
      }))
    })), {})
    target_object_key_format = optional(map(object({
      partitioned_prefix = optional(map(object({
        partition_date_source = string
      })), {})
      simple_prefix = optional(object({}))
    })), {})
  }))
  default = {}
}

variable "versioning" {
  description = "The S3 bucket versioning configuration"
  type = map(object({
    expected_bucket_owner = optional(string)
    mfa                   = optional(string)

    versioning_configuration = object({
      status     = optional(string)
      mfa_delete = optional(string)
    })
  }))
  default = {}
}

variable "encryption_configuration" {
  description = "The S3 bucket server-side encryption configuration"
  type = map(object({
    expected_bucket_owner = optional(string)

    rule = object({
      apply_server_side_encryption_by_default = optional(object({
        sse_algorithm     = string
        kms_master_key_id = optional(string)
      }))

      bucket_key_enabled = optional(bool)
    })
  }))
  default = {}
}

variable "lifecycle_configuration" {
  description = "The S3 bucket lifecycle configuration"
  type = map(object({
    expected_bucket_owner                  = optional(string)
    transition_default_minimum_object_size = optional(string)

    rule = list(object({
      status = string
      id     = string

      abort_incomplete_multipart_upload = optional(map(object({
        days_after_initiation = optional(number)
      })), {})

      expiration = optional(object({
        date                         = optional(string)
        days                         = optional(number)
        expired_object_delete_marker = optional(bool)
      }), {})

      filter = optional(map(object({
        and = optional(list(object({
          object_size_greater_than = optional(number)
          object_size_less_than    = optional(number)
          prefix                   = optional(string)
        })), [])

        object_size_greater_than = optional(number)
        object_size_less_than    = optional(number, )
        prefix                   = optional(string)
      })), {})

      noncurrent_version_expiration = optional(map(object({
        newer_noncurrent_versions = optional(number)
        noncurrent_days           = optional(number)
      })), {})

      noncurrent_version_transition = optional(map(object({
        newer_noncurrent_versions = optional(number)
        noncurrent_days           = optional(number)
        storage_class             = optional(string)
      })), {})

      transition = optional(map(object({
        date          = optional(string)
        days          = optional(number)
        storage_class = optional(string)
      })), {})
    }))
  }))
  default = {}
}

variable "public_access_block" {
  description = "The S3 public access block configuration"
  type = map(object({
    restrict_public_buckets = optional(bool)
    block_public_acls       = optional(bool)
    block_public_policy     = optional(bool)
    ignore_public_acls      = optional(bool)
  }))
  default = {}
}

variable "replication_configuration" {
  description = "The S3 bucket replication configuration"
  type = map(object({
    bucket = string
    role   = string
    token  = optional(string)

    rule = list(object({
      id       = optional(string)
      priority = optional(number)
      status   = string

      delete_marker_replication = optional(object({
        status = optional(string)
      }), {})

      existing_object_replication = optional(object({
        status = optional(string)
      }), {})

      filter = optional(object({
        prefix = optional(string)
        and = optional(list(object({
          prefix = optional(string)
        })), [])
      }), {})

      source_selection_criteria = optional(object({
        replica_modifications = optional(object({
          status = optional(string)
        }), {})

        sse_kms_encrypted_objects = optional(object({
          status = optional(string)
        }), {})
      }))

      destination = object({
        account       = optional(string)
        bucket        = string
        storage_class = optional(string)

        access_control_translation = optional(object({
          owner = optional(string)
        }))

        encryption_configuration = optional(object({
          replica_kms_key_id = optional(string)
        }), {})

        rule = optional(object({
          replica_kms_key_id = string
        }))

        metrics = optional(object({
          event_threshold = optional(object({
            minutes = optional(number)
          }), {})

          status = optional(string)
        }), {})

        replication_time = optional(object({
          status = optional(string)

          time = optional(object({
            minutes = optional(number)
          }), {})
        }), {})
      })
    }))
  }))
  default = {}
}

variable "acls" {
  description = "The S3 bucket ACL configuration"
  type = map(object({
    expected_bucket_owner = optional(string)
    acl                   = optional(string)

    access_control_policy = optional(object({
      grant = optional(list(object({
        grantee = optional(object({
          id            = optional(string)
          type          = optional(string)
          uri           = optional(string)
          email_address = optional(string)
        }), {})

        permission = optional(string)
      })), [])

      owner = optional(object({
        id           = optional(string)
        display_name = optional(string)
      }), {})
    }), {})
  }))
  default = {}
}

variable "website_configuration" {
  description = "The S3 bucket website configuration"
  type = map(object({
    bucket                = string
    expected_bucket_owner = optional(string)
    index_document        = optional(string)
    error_document        = optional(string)

    redirect_all_requests_to = optional(object({
      host_name = string
      protocol  = optional(string)
    }))

    routing_rule = optional(object({
      condition = optional(object({
        http_error_code_returned_equals = optional(string)
        key_prefix_equals               = optional(string)
      }), {})

      redirect = optional(object({
        host_name               = optional(string)
        http_redirect_code      = optional(string)
        protocol                = optional(string)
        replace_key_prefix_with = optional(string)
        replace_key_with        = optional(string)
      }), {})
    }))
  }))
  default = {}
}

variable "buckets_cors" {
  description = "Map of S3 bucket IDs to their respective CORS configurations"
  type = map(object({
    cors_rules = list(object({
      allowed_headers = list(string)
      allowed_methods = list(string)
      allowed_origins = list(string)
      expose_headers  = optional(list(string))
      max_age_seconds = optional(number)
    }))
  }))
  default = {}
}
##################################################
#endregion
##################################################