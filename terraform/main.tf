###############################################################################
# INSECURE BY DESIGN Terraform.
#
# This describes AWS infrastructure riddled with the misconfigurations that IaC
# scanners (Checkov, Trivy, tfsec, Terrascan) are built to catch. You do NOT
# need to `terraform apply` this — in fact you shouldn't. IaC scanning is a
# STATIC analysis of these files, so `checkov -d terraform/` finds every issue
# below without an AWS account and without creating a single resource.
#
# If you DO want to see it live, run `terraform plan` only (no apply) with a
# free-tier AWS account. Each misconfiguration is annotated with the kind of
# finding and a representative Checkov policy id.
###############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# S3 bucket: public, unencrypted, unversioned, unlogged.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "data" {
  bucket = "devsecops-lab-insecure-data-bucket"
}

# BAD: public-read ACL exposes objects to the whole internet.
# (CKV_AWS_20 — S3 bucket should not be public)
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# BAD: no aws_s3_bucket_server_side_encryption_configuration
#   -> data at rest is unencrypted (CKV_AWS_19).
# BAD: no aws_s3_bucket_versioning
#   -> no protection against overwrite/delete (CKV_AWS_21).
# BAD: no aws_s3_bucket_public_access_block
#   -> nothing stops the public ACL above (CKV2_AWS_6).
# BAD: no aws_s3_bucket_logging
#   -> no access audit trail (CKV_AWS_18).

# ---------------------------------------------------------------------------
# Security group: wide open to the internet.
# ---------------------------------------------------------------------------
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Allows everything from anywhere (do not do this)"

  # BAD: SSH open to 0.0.0.0/0 (CKV_AWS_24).
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # BAD: RDP open to 0.0.0.0/0 (CKV_AWS_25).
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # BAD: all ports, all protocols, egress to anywhere.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# RDS database: public, unencrypted, hardcoded password, no backups.
# ---------------------------------------------------------------------------
resource "aws_db_instance" "database" {
  identifier          = "devsecops-lab-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"

  # BAD: hardcoded credential in source (CWE-798). Secrets scanners AND IaC
  # scanners flag this. Use a secrets manager / random_password instead.
  password            = "SuperSecretPassword123!"

  # BAD: reachable from the public internet (CKV_AWS_17).
  publicly_accessible = true

  # BAD: storage not encrypted at rest (CKV_AWS_16).
  storage_encrypted   = false

  # BAD: zero-day backup retention disables automated backups (CKV_AWS_293).
  backup_retention_period = 0

  skip_final_snapshot = true
}

# ---------------------------------------------------------------------------
# IAM policy: full admin wildcard.
# ---------------------------------------------------------------------------
# BAD: Action "*" on Resource "*" grants god-mode, violating least privilege
# (CKV_AWS_1 / CKV_AWS_289). Scope policies to specific actions and ARNs.
resource "aws_iam_policy" "admin" {
  name = "lab-full-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
