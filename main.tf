locals {
  name = "autocap"
}

# Create a custom VPC
resource "aws_vpc" "vpc" {
  cidr_block = var.cidr
   enable_dns_support   = true
  enable_dns_hostnames = true

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
    Name = "${local.name}-pub-sn1"
  }
}
#  Create Public subnet 2
resource "aws_subnet" "pub_sn2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.pub_sn2
  availability_zone       = "eu-west-3b"

  tags = {
    Name = "${local.name}-pub-sn2"
  }
}

#  Create Private subnet 1
resource "aws_subnet" "prv_sn1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.prv_sn1
  availability_zone       = "eu-west-3a"
  tags = {
    Name = "${local.name}-prv-sn1"
  }
}

#  Create Private subnet 2
resource "aws_subnet" "prv_sn2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.prv_sn2
  availability_zone       = "eu-west-3b"
  
  tags = {
    Name = "${local.name}-prv-sn2"
  }
}

# Creating internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
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
    Name = "${local.name}-pub-rt"
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
    Name = "${local.name}-prv-rt"
  }

  depends_on = [aws_nat_gateway.ngw]  
}


# Attaching public subnet 1 to public route table
resource "aws_route_table_association" "pub_rt_asso1" {
  subnet_id      = aws_subnet.pub_sn1.id
  route_table_id = aws_route_table.pub_rt.id
}

# Attaching public subnet 2 to public route table
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

# Creating Elastic IP for Nat Gateway
resource "aws_eip" "eip" {
  domain = "vpc"
  tags = {
    Name = "${local.name}-eip"
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
# Creating Security Groups
#Front-end Security Group 
resource "aws_security_group" "frontend_sg" {
  name   = "${local.name}-frontend-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    description = "Allow ssh inbound traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
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
    description = "Allow http inbound traffic"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
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
    Name = "${local.name}-frontend-sg"
  }
}

# Creating RDS Security group
resource "aws_security_group" "rds_sg" {
  name   = "${local.name}-rds-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    description     = "Allow MySQL from EC2"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"] # restrict egress to your VPC CIDR
  }

  tags = {
    Name = "${local.name}-rds-sg"
  }
}


resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "private_key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "wordpress_key.pem"
  file_permission = "600"
}

resource "aws_key_pair" "key" {
  key_name   = "${local.name}-pub-key"
  public_key = tls_private_key.key.public_key_openssh
}
# IAM Role for EC2 instances
resource "aws_iam_role" "wordpress_ec2_role" {
  name = "${local.name}-wordpress-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# IAM Instance Profile to associate the Role with EC2 instances
resource "aws_iam_instance_profile" "wordpress_instance_profile" {
  name = "${local.name}-wordpress-instance-profile"
  role = aws_iam_role.wordpress_ec2_role.name
}

# IAM Policy with Least Privilege permissions for the role
resource "aws_iam_policy" "wordpress_ec2_policy" {
  name = "${local.name}-wordpress-ec2-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "logs:*", "secretsmanager:GetSecretValue"]
      Resource = "*"
    }]
  })
}
# Attach the Policy to the Role
resource "aws_iam_role_policy_attachment" "wordpress_policy_attach" {
  role       = aws_iam_role.wordpress_ec2_role.name
  policy_arn = aws_iam_policy.wordpress_ec2_policy.arn
}
# WordPress EC2 Instance
resource "aws_instance" "wordpress_server" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.pub_sn1.id   # public subnet
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.frontend_sg.id]

  iam_instance_profile = aws_iam_instance_profile.wordpress_instance_profile.name
  key_name             = aws_key_pair.key.key_name

  # Inject cleaned WordPress user data
  user_data = local.wordpress_script

  tags = {
    Name = "${local.name}-wordpress-server"
  }
}

# Make sure the instance is accessible via Load Balancer
resource "aws_lb_target_group_attachment" "lb_attachment_http" {
  target_group_arn = aws_lb_target_group.wordpress_http_tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "lb_attachment_https" {
  target_group_arn = aws_lb_target_group.wordpress_https_tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = 443
}

# Amazon machine image (AMI) for the backend instance
resource "time_sleep" "ami_wait" {
  depends_on      = [aws_instance.wordpress_server]
  create_duration = "300s" # Wait 5 minutes to allow system initialization
}

resource "aws_ami_from_instance" "custom_ami" {
  name = "${local.name}-wordpress-custom-ami"
  source_instance_id = aws_instance.wordpress_server.id
  snapshot_without_reboot = true
  depends_on = [
    time_sleep.ami_wait
  ]
}

# #insert secret manager here
resource "aws_secretsmanager_secret" "db_cred" {
  name        = "${local.name}-wordpress-db-credentials2"
  description = "Database credentials for the WordPress application"
}

resource "aws_secretsmanager_secret_version" "db_cred_version" {
  secret_id     = aws_secretsmanager_secret.db_cred.id
  secret_string = jsonencode(var.dbcred)
}

#database
# Create a DB Subnet Group
resource "aws_db_subnet_group" "wordpress_db_subnet" {
  name       = "${local.name}-wordpress-db-subnet"
  subnet_ids = [aws_subnet.prv_sn1.id, aws_subnet.prv_sn2.id]
}

#Create RDS MySQL Instance
resource "aws_db_instance" "wordpress_db" {
  identifier             = "${local.name}-wordpress-db"
  allocated_storage      = 20
  max_allocated_storage  = 100
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = var.dbcred["username"]
  password               = var.dbcred["password"]
  db_subnet_group_name   = aws_db_subnet_group.wordpress_db_subnet.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  parameter_group_name   = "default.mysql8.0"
  db_name                = var.db_name
  skip_final_snapshot    = true
  publicly_accessible    = true
  multi_az               = true

  tags = {
    Name = "${local.name}-wordpress-db"
  }
}

#application load balancer
resource "aws_lb" "wordpress_alb" {
  name               = "${local.name}-wordpress-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.frontend_sg.id]
  subnets = [
    aws_subnet.pub_sn1.id,
    aws_subnet.pub_sn2.id
  ]
  enable_deletion_protection = false

  tags = {
    Name = "${local.name}-wordpress-alb"
  }
}

#application target group
resource "aws_lb_target_group" "wordpress_http_tg" {
  name     = "${local.name}-wordpress-http-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    path                = "/indextest.html"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
    port                = 80
  }

  tags = {
    Name = "${local.name}-wordpress-http-tg"
  }
}
# HTTTPS Target Group
resource "aws_lb_target_group" "wordpress_https_tg" {
  name     = "${local.name}-wordpress-https-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    path                = "/indextest.html"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
    port                = 443
  }

  tags = {
    Name = "${local.name}-wordpress-https-tg"
  }
}

# launch template
resource "aws_launch_template" "launch_template" {
  name_prefix   = "${local.name}-lt-"
  image_id      = aws_ami_from_instance.custom_ami.id
  instance_type = "t2.medium"
  key_name      = aws_key_pair.key.key_name
  iam_instance_profile {
    name = aws_iam_instance_profile.wordpress_instance_profile.name
  }
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.frontend_sg.id]
  }
  user_data = base64encode(local.wordpress_script)
}

#auto scaling policy
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "${local.name}-scale-out-policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

# Autoscaling group
resource "aws_autoscaling_group" "asg" {
  name                      = "${local.name}-asg"
  desired_capacity          = 2
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  force_delete              = true
  launch_template {
    id      = aws_launch_template.launch_template.id
    version = "$Latest"
  }
  vpc_zone_identifier = [
    aws_subnet.pub_sn1.id,
    aws_subnet.pub_sn2.id
  ]
  target_group_arns = [
    aws_lb_target_group.wordpress_http_tg.arn,
    aws_lb_target_group.wordpress_https_tg.arn
  ]
}
# ACM Certificate
resource "aws_acm_certificate" "acm_cert" {
  domain_name       = "odochidevops.space"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}


#insert two target groups. one for http and another for https here

#load balancer listener
resource "aws_lb_listener" "wordpress_https_listener" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.acm_cert.arn
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_https_tg.arn
  }
}
# Reference the Route53 hosted zone
data "aws_route53_zone" "main_zone" {
  name         = "odochidevops.space"   # your domain name
  private_zone = false
}

# ROUTE53 RECORD FOR ACM VALIDATION
resource "aws_route53_record" "validate_record" {
  for_each = {
    for dvo in aws_acm_certificate.acm_cert.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main_zone.zone_id
}

resource "aws_acm_certificate_validation" "cert_validation" {
  certificate_arn         = aws_acm_certificate.acm_cert.arn
  validation_record_fqdns = [for r in aws_route53_record.validate_record : r.fqdn]
}
# SNS Topic for Server Alerts
resource "aws_sns_topic" "server_alert" {
  name = "${local.name}server-alert"
}

# CloudWatch Metric Alarm for High CPU
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "ASG-High-CPU"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "Triggers scale out when CPU exceeds 70%"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_actions = [
    aws_autoscaling_policy.scale_out.arn,
    aws_sns_topic.server_alert.arn
  ]
}

locals {
  s3_origin_id = aws_s3_bucket.media_bucket.id
}

resource "aws_s3_bucket" "media_bucket" {
  bucket        = "${local.name}-media-bucket"
  force_destroy = true

  tags = {
    Name = "${local.name}-media-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "media_bucket_pab" {
  bucket                  = aws_s3_bucket.media_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "media_bucket_ownership" {
  bucket = aws_s3_bucket.media_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }

  depends_on = [aws_s3_bucket_public_access_block.media_bucket_pab]
}

data "aws_iam_policy_document" "media_bucket_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]  # Replace with CloudFront OAI later if private
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.media_bucket.arn,
      "${aws_s3_bucket.media_bucket.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "media_bucket_policy" {
  bucket = aws_s3_bucket.media_bucket.id
  policy = data.aws_iam_policy_document.media_bucket_policy.json
}
resource "aws_s3_bucket" "code_bucket" {
  bucket        = "${local.name}-code-bucket"
  force_destroy = true

  tags = {
    Name = "${local.name}-code-bucket"
  }
}
resource "aws_iam_policy" "s3_access_policy" {
  name = "${local.name}-s3-access-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.media_bucket.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.media_bucket.arn}/*"
        ]
      }
    ]
  })
}
resource "aws_iam_role" "ec2_role" {
  name = "${local.name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "${local.name}-ec2-role"
  }
}

resource "aws_iam_role_policy_attachment" "s3_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${local.name}-instance-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_s3_bucket" "log_bucket" {
  bucket        = "${local.name}-log-bucket"
  force_destroy = true

  tags = {
    Name = "${local.name}-log-bucket"
  }
}

resource "aws_s3_bucket_ownership_controls" "log_bucket_ownership" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "log_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.log_bucket_ownership]
  bucket     = aws_s3_bucket.log_bucket.id
  acl        = "log-delivery-write"
}

data "aws_iam_policy_document" "log_bucket_policy" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
      "s3:GetBucketAcl"
    ]

    resources = [
      aws_s3_bucket.log_bucket.arn,
      "${aws_s3_bucket.log_bucket.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket = aws_s3_bucket.log_bucket.id
  policy = data.aws_iam_policy_document.log_bucket_policy.json
}


resource "aws_s3_bucket_public_access_block" "log_bucket_access_block" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}


resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.media_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.log_bucket.bucket_regional_domain_name
    prefix          = "cloudfront-log"
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 3600
    default_ttl            = 86400
    max_ttl                = 31536000
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  tags = { Name = "cloudfront" }

  viewer_certificate { cloudfront_default_certificate = true }
}

data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}



