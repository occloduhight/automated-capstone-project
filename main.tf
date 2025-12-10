locals {
  name = "autocap"
  s3_origin_id  = aws_s3_bucket.autocap_media.id
}

# Create a custom VPC
resource "aws_vpc" "vpc" {
  cidr_block = var.cidr
  instance_tenancy = "default"
  #  enable_dns_support   = true
  # enable_dns_hostnames = true

  tags = {
    Name = "${local.name}-vpc"
  }
}
#  Create Public subnet 1
resource "aws_subnet" "pub_sn1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.pub_sn1
  availability_zone       = "eu-west-3a"

  tags = {
    Name = "${local.name}-pub_sn1"
  }
}
#  Create Public subnet 2
resource "aws_subnet" "pub_sn2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.pub_sn2
  availability_zone       = "eu-west-3b"

  tags = {
    Name = "${local.name}-pub_sn2"
  }
}

#  Create Private subnet 1
resource "aws_subnet" "prv_sn1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.prv_sn1
  availability_zone       = "eu-west-3a"
  tags = {
    Name = "${local.name}-prv_sn1"
  }
}

#  Create Private subnet 2
resource "aws_subnet" "prv_sn2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.prv_sn2
  availability_zone       = "eu-west-3b"
  
  tags = {
    Name = "${local.name}-prv_sn2"
  }
}

# Creating internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}

# Create Nat Gateway
resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_sn1.id

  tags = {
    Name = "${local.name}-ngw"
  }
  depends_on = [aws_internet_gateway.igw]
}

# Creating Elastic IP for Nat Gateway
resource "aws_eip" "eip" {
  domain = "vpc"
  tags = {
    Name = "${local.name}-eip"
  }
}


# Creating public route table
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${local.name}-pub_rt"
  }
}

# Creating private route table
resource "aws_route_table" "prv_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.ngw.id
  }

  tags = {
    Name = "${local.name}-prv_rt"
  }

  # depends_on = [aws_nat_gateway.ngw]  
}

# Creating route table association public subnet 1
resource "aws_route_table_association" "pub_rt_asso1" {
  subnet_id      = aws_subnet.pub_sn1.id
  route_table_id = aws_route_table.pub_rt.id
}

# Creating route table association public subnet 2
resource "aws_route_table_association" "pub_rt_asso2" {
  subnet_id      = aws_subnet.pub_sn2.id
  route_table_id = aws_route_table.pub_rt.id
}

# Associating private subnet 1 to private route table
resource "aws_route_table_association" "prv_rt_asso1" {
  subnet_id      = aws_subnet.prv_sn1.id
  route_table_id = aws_route_table.prv_rt.id
}

# Associating private subnet 2 to  private route table
resource "aws_route_table_association" "prv_rt_asso2" {
  subnet_id      = aws_subnet.prv_sn2.id
  route_table_id = aws_route_table.prv_rt.id
}

#Creating Front-end Security Group 
resource "aws_security_group" "autocap_sg" {
  name   = "${local.name}-autocap_sg"
  vpc_id = aws_vpc.vpc.id

ingress {
    description = "Allow http inbound traffic"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow https inbound traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow ssh inbound traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-autocap_sg"
  }
}

# Creating RDS Security group
# RDS Security Group (correct for your architecture)
resource "aws_security_group" "rds_sg" {
  name        = "${local.name}-rds_sg"
  description = "Allow MySQL from EC2 in public subnets"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.pub_sn1, var.pub_sn2]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-rds_sg"
  }
}
# Key Pair
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "private_key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "autocap_key.pem"
  file_permission = "600"
}

resource "aws_key_pair" "key" {
  key_name   = "autocap_pub_key"
  public_key = tls_private_key.key.public_key_openssh
}

# S3 Buckets
resource "aws_s3_bucket" "autocap_media" {
  bucket        = "autocap-media"
  force_destroy = true

  tags = {
    Name = "${local.name}-autocap-media"
  }
}

resource "aws_s3_bucket_public_access_block" "autocap_media_pub" {
  bucket                  = aws_s3_bucket.autocap_media.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "autocap_media_ctrl" {
  bucket = aws_s3_bucket.autocap_media.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }

  depends_on = [aws_s3_bucket_public_access_block.autocap_media_pub]
}

data "aws_iam_policy_document" "autocap_media_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetObjectVersion"
    ]

    resources = [
      aws_s3_bucket.autocap_media.arn,
      "${aws_s3_bucket.autocap_media.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "autocap_media_policy" {
  bucket = aws_s3_bucket.autocap_media.id
  policy = data.aws_iam_policy_document.autocap_media_policy.json
}

resource "aws_s3_bucket" "code_bucket" {
  bucket        = "autocap-code-bucket"
  force_destroy = true

  tags = {
    Name = "${local.name}-autocap-code-bucket"
  }
}
# IAM Role and Policies
resource "aws_iam_role" "iam_role" {
  name = "${local.name}-iam_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    Name = "${local.name}-iam_role"
  }
}

resource "aws_iam_policy" "s3_policy" {
  name   = "acp-s3-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = ["s3:*"]
      Resource = "*"
      Effect   = "Allow"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "iam_s3_attachment" {
  role       = aws_iam_role.iam_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
}

resource "aws_iam_instance_profile" "iam_instance_profile" {
  name = "${local.name}-instance_profile"
  role = aws_iam_role.iam_role.name
}

# Log Bucket
resource "aws_s3_bucket" "autocap_log_bucket" {
  bucket        = "autocap-log-bucket"
  force_destroy = true

  tags = {
    Name = "${local.name}-autocap_log_bucket"
  }
}

# resource "aws_s3_bucket" "autocap_log_bucket" {
#   bucket        = "autocap-log-bucket"
#   force_destroy = true

#   tags = {
#     Name = "${local.name}-autocap-log-bucket"
#   }
# }

resource "aws_s3_bucket_public_access_block" "log_bucket_access_block" {
  bucket                  = aws_s3_bucket.autocap_log_bucket.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

data "aws_iam_policy_document" "log_bucket_access_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:PutObject"
    ]

    resources = [
      aws_s3_bucket.autocap_log_bucket.arn,
      "${aws_s3_bucket.autocap_log_bucket.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "autocap_log_bucket_policy" {
  bucket = aws_s3_bucket.autocap_log_bucket.id
  policy = data.aws_iam_policy_document.log_bucket_access_policy.json
}

# DB Subnet Group
resource "aws_db_subnet_group" "database" {
  name       = "database"
  subnet_ids = [aws_subnet.prv_sn1.id, aws_subnet.prv_sn2.id]

  tags = {
    Name = "${local.name}-DB-subnet"
  }
}

# RDS Instance
resource "aws_db_instance" "wordpress_db" {
  identifier             = "${local.name}-wordpress-db"
  db_subnet_group_name   = aws_db_subnet_group.database.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  allocated_storage      = 10
  db_name                = var.db_name
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = var.username
  password               = var.password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}


resource "aws_s3_bucket_acl" "log_bucket_acl" {
  bucket = aws_s3_bucket.autocap_log_bucket.id
  acl    = "log-delivery-write"

  depends_on = [
    aws_s3_bucket_ownership_controls.log_bucket_owner
  ]
}

data "aws_iam_policy_document" "log_bucket_policy" {
  statement {
    sid    = "AWSCloudFrontLogsPolicy"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::127311923021:root" # CloudFront log delivery service account (us-east-1)
      ]
    }

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.autocap_log_bucket.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket = aws_s3_bucket.autocap_log_bucket.id
  policy = data.aws_iam_policy_document.log_bucket_policy.json
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.autocap_media.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.autocap_log_bucket.bucket_domain_name
    prefix          = "cloudfront-log"
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  price_class = "PriceClass_All"

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "${local.name}-cloudfront"
  }

  depends_on = [
    aws_s3_bucket.autocap_log_bucket,
    aws_s3_bucket_acl.log_bucket_acl
  ]
}

data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}

resource "aws_s3_bucket_ownership_controls" "log_bucket_owner" {
  bucket = aws_s3_bucket.autocap_log_bucket.id

  rule {
    # CloudFront requires ACLs — ObjectWriter allows ACL usage
    object_ownership = "ObjectWriter"
  }
}

# EC2 Instance
resource "aws_instance" "wordpress_server" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.autocap_sg.id, aws_security_group.rds_sg.id]
  subnet_id                   = aws_subnet.pub_sn1.id
  iam_instance_profile        = aws_iam_instance_profile.iam_instance_profile.id
  key_name                    = aws_key_pair.key.key_name
 user_data = templatefile("wordpress_script.sh.tpl", {
  db_name         = var.db_name
  db_username     = var.username
  db_password     = var.password     # <-- matches template
  db_host         = aws_db_instance.wordpress_db.address
  cloudfront_domain = data.aws_cloudfront_distribution.cloudfront.domain_name
})




  tags = {
    Name = "${local.name}-wordpress_server"
  }
}

