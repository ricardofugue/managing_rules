__rego__metadoc__ := {
  "title": "S3 Block Public Access",
  "description": "Block Public Access must be on unless in an exception list",
  "custom": {
    "providers": ["Repository","AWS"],
    "severity": "Critical"
  }
}

resource_type = "MULTIPLE"

buckets = fugue.resources("aws_s3_bucket")
blocks = fugue.resources("aws_s3_bucket_public_access_block")

is_valid_bucket = {
  "ricardo-testbucket-1",
  "my-public-bucket"
}
    # can add your list of bucket IDs that are allowed to be public
    
has_public_block(bucket) {
    block = blocks[_]
    bucket.id = block.bucket
    block.block_public_acls == true
    block.ignore_public_acls == true
    block.block_public_policy == true
    block.restrict_public_buckets == true
}

is_valid_overall(bucket) {
  is_valid_bucket[bucket.id]
 } {
  has_public_block(bucket)
 }

policy[r]  {
    #allow if public access block is on or if it's on the exception list
    bucket = buckets[_]
    is_valid_overall(bucket)
    r = fugue.allow_resource(bucket)
} {
    bucket = buckets[_]
    not is_valid_overall(bucket)
    #if resource isn't on the list and doesn't have public access block
    r = fugue.deny_resource(bucket)
}
