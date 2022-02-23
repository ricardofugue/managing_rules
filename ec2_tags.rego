package rules.ec2_tags

import data.fugue

__rego__metadoc__ := {
  "title": "EC2 Instances must have 'application' tag",
  "description": "An application tag must be present on all EC2 Instances.",
  "custom": {
    "providers": ["Repository","AWS"],
    "severity": "Medium"
  }
}

resource_type = "aws_instance"

allow {
  input.tags.application
}{
  input.tags.Application
}
