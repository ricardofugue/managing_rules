package rules.ebs_encryption

import data.fugue

__rego__metadoc__ := {
  "title": "EBS Volume Encryption",
  "description": "All EBS Volumes must be encrypted.",
  "custom": {
    "providers": ["Repository","AWS"],
    "severity": "High"
  }
}

resource_type = "aws_ebs_volume"

default allow = false

allow {
  input.encrypted == true
}