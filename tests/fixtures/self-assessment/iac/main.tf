# Intentionally misconfigured Terraform, used only to validate that
# Checkov (Layer 6: IaC Security) actually flags real misconfigurations.
# Do NOT apply this — it is a scan fixture, not real infrastructure.

resource "aws_security_group" "self_assessment_open_ingress" {
  name        = "epyon-self-assessment-open-sg"
  description = "Intentionally open ingress rule (CKV_AWS_24 / CKV_AWS_260)"

  ingress {
    description = "Wide open SSH — planted misconfiguration for scanner validation"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "self_assessment_unencrypted" {
  bucket = "epyon-self-assessment-bucket"
  # Intentionally no server_side_encryption_configuration block (CKV_AWS_19)
}

resource "aws_db_instance" "self_assessment_public_db" {
  identifier          = "epyon-self-assessment-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 10
  publicly_accessible = true # Intentional (CKV_AWS_17)
  skip_final_snapshot = true
}
