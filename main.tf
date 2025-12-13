locals {
  name        = "autocap"
  email       = "chinweodochi@gmail.com"
  db_cred     = var.db_cred
  s3_origin_id = aws_s3_bucket.autocap_media.id
}

# VPC & Subnets
resource "aws_vpc" "vpc" {
  cidr_block       = var.cidr
  instance_tenancy = "default"

  tags = { Name = "${local.name}-vpc" }
}

resource "aws_subnet" "pub_sn1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.pub_sn1
  availability_zone = "eu-west-3a"

  tags = { Name = "${local.name}-pub_sn1" }
}

resource "aws_subnet" "pub_sn2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.pub_sn2
  availability_zone = "eu-west-3b"

  tags = { Name = "${local.name}-pub_sn2" }
}

resource "aws_subnet" "prv_sn1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.prv_sn1
  availability_zone = "eu-west-3a"

  tags = { Name = "${local.name}-prv_sn1" }
}

resource "aws_subnet" "prv_sn2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.prv_sn2
  availability_zone = "eu-west-3b"

  tags = { Name = "${local.name}-prv_sn2" }
}

##########################
# Internet & NAT Gateway
##########################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = { Name = "${local.name}-igw" }
}

resource "aws_eip" "eip" {
  domain = "vpc"

  tags = { Name = "${local.name}-eip" }
}

resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_sn1.id

  tags = { Name = "${local.name}-ngw" }
  depends_on = [aws_internet_gateway.igw]
}

##########################
# Route Tables
##########################
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${local.name}-pub_rt" }
}

resource "aws_route_table" "prv_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.ngw.id
  }

  tags = { Name = "${local.name}-prv_rt" }
}

resource "aws_route_table_association" "pub_rt_asso1" {
  subnet_id      = aws_subnet.pub_sn1.id
  route_table_id = aws_route_table.pub_rt.id
}

resource "aws_route_table_association" "pub_rt_asso2" {
  subnet_id      = aws_subnet.pub_sn2.id
  route_table_id = aws_route_table.pub_rt.id
}

resource "aws_route_table_association" "prv_rt_asso1" {
  subnet_id      = aws_subnet.prv_sn1.id
  route_table_id = aws_route_table.prv_rt.id
}

resource "aws_route_table_association" "prv_rt_asso2" {
  subnet_id      = aws_subnet.prv_sn2.id
  route_table_id = aws_route_table.prv_rt.id
}

##########################
# Security Groups
##########################
resource "aws_security_group" "autocap_sg" {
  name   = "${local.name}-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    description = "HTTP"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
      description = "HTTPS"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-sg" }
}

resource "aws_security_group" "rds_sg" {
  name        = "${local.name}-rds_sg"
  description = "Allow outbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "MYSQPORT"
    from_port   = var.mysqlport
    to_port     = var.mysqlport
    protocol        = "tcp"
    # security_groups = [aws_security_group.autocap_sg.id]
     cidr_blocks = ["${var.pub_sn1}", "${var.pub_sn1}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-rds_sg" }
}

##########################
# Key Pair
##########################
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

# IAM Policy for EC2 to access S3, RDS, and network interfaces
resource "aws_iam_policy" "ec2_permissions" {
  name = "${local.name}-ec2_policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "ec2:DetachNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:AttachNetworkInterface",
          "rds:DescribeDBInstances",
          "rds:ModifyDBInstance",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach IAM Policy to Role
resource "aws_iam_role_policy_attachment" "attach_ec2_policy" {
  role       = aws_iam_role.iam_role.name
  policy_arn = aws_iam_policy.ec2_permissions.arn
}

resource "aws_iam_policy" "s3_policy" {
  name   = "${local.name}-s3-policy"
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

##########################
# S3 Buckets
##########################
resource "aws_s3_bucket" "autocap_media" {
  bucket        = "autocap-media"
  force_destroy = true

  tags = { Name = "${local.name}-media" }
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

  rule { object_ownership = "BucketOwnerEnforced" }

  depends_on = [aws_s3_bucket_public_access_block.autocap_media_pub]
}

data "aws_iam_policy_document" "autocap_media_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetObjectVersion"
    ]

    resources = [
      aws_s3_bucket.autocap_media.arn,
      "${aws_s3_bucket.autocap_media.arn}/*"
    ]
  }
}


resource "aws_s3_bucket_policy" "autocap_media_policy" {
  bucket = aws_s3_bucket.autocap_media.id
  policy = data.aws_iam_policy_document.autocap_media_policy.json
}

# S3 code Bucket 
resource "aws_s3_bucket" "code_bucket" {
  bucket = "autocap-code-bucket"
  # depends_on = [ null_resource.pre_scan ]
  force_destroy = true

  tags = {
    Name = "${local.name}-code-bucket"
  }
}
resource "aws_s3_bucket" "alb_log_bucket" {
  bucket        = "autocap-alb-log-bucket"
  force_destroy = true
  tags = { Name = "${local.name}-alb-log-bucket" }
}

resource "aws_s3_bucket_public_access_block" "alb_log_block" {
  bucket                  = aws_s3_bucket.alb_log_bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "alb_log_owner" {
  bucket = aws_s3_bucket.alb_log_bucket.id
  rule   { object_ownership = "BucketOwnerEnforced" }
}
data "aws_iam_policy_document" "alb_log_policy" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_log_bucket.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["elasticloadbalancing.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
resource "aws_s3_bucket_policy" "alb_log_bucket_policy" {
  bucket = aws_s3_bucket.alb_log_bucket.id
  policy = data.aws_iam_policy_document.alb_log_policy.json
}
# data "aws_iam_policy_document" "alb_log_policy" {
#   statement {
#     principals {
#       type        = "Service"
#       identifiers = ["elasticloadbalancing.amazonaws.com"]
#     }

#     actions   = ["s3:PutObject"]

#     resources = [
# #       "${aws_s3_bucket.alb_log_bucket.arn}/*"
#     ]
#   }
# }


# resource "aws_s3_bucket_policy" "alb_log_bucket_policy" {
#   bucket = aws_s3_bucket.alb_log_bucket.id
#   policy = data.aws_iam_policy_document.alb_log_policy.json
# }

resource "aws_s3_bucket" "cloudfront_log_bucket" {
  bucket        = "autocap-cloudfront-log-bucket"
  force_destroy = true
  tags = { Name = "${local.name}-cloudfront-log-bucket" }
}

resource "aws_s3_bucket_public_access_block" "cloudfront_log_block" {
  bucket                  = aws_s3_bucket.cloudfront_log_bucket.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cloudfront_log_owner" {
  bucket = aws_s3_bucket.cloudfront_log_bucket.id
  rule   { object_ownership = "ObjectWriter" }
}

resource "aws_s3_bucket_acl" "cloudfront_log_acl" {
  bucket = aws_s3_bucket.cloudfront_log_bucket.id
  acl    = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.cloudfront_log_owner]
}

##########################
# RDS
##########################
resource "aws_db_subnet_group" "database" {
  name       = "database"
  subnet_ids = [aws_subnet.prv_sn1.id, aws_subnet.prv_sn2.id]
  tags       = { Name = "${local.name}-db-subnet" }
}

resource "aws_db_instance" "wordpress_db" {
  identifier             = var.db_identifier
  db_subnet_group_name   = aws_db_subnet_group.database.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  allocated_storage      = 10
  db_name                = var.dbname
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = local.db_cred.username
  password               = local.db_cred.password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}
##########################
# EC2 Instance
##########################
resource "aws_instance" "wordpress_server" {
  ami                    = var.redhat_ami
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.pub_sn1.id
  associate_public_ip_address = true
  vpc_security_group_ids = [aws_security_group.autocap_sg.id, aws_security_group.rds_sg.id]
  key_name               = aws_key_pair.key.key_name
  iam_instance_profile   = aws_iam_instance_profile.iam_instance_profile.id
  user_data              = local.wordpress_script
   depends_on = [
    aws_db_instance.wordpress_db,
    aws_cloudfront_distribution.s3_distribution
  ]

  tags = { Name = "${local.name}-wordpress_server" }
}

##########################
# AMI from Instance (for AutoScaling)
##########################
resource "time_sleep" "ami_sleep" {
  create_duration = "360s"
  depends_on      = [aws_instance.wordpress_server]
}

resource "aws_ami_from_instance" "asg_ami" {
  name                    = "asg-ami"
  source_instance_id      = aws_instance.wordpress_server.id
  snapshot_without_reboot = true
  depends_on              = [time_sleep.ami_sleep]
}

##########################
# Launch Template
##########################
resource "aws_launch_template" "lnch_lt" {
  name_prefix   = "${local.name}-web_lt"
  image_id      = aws_ami_from_instance.asg_ami.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.key.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.iam_instance_profile.name
  }

  network_interfaces {
    device_index               = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.autocap_sg.id]
  }

  # user_data = local.wordpress_script
   user_data = base64encode(local.wordpress_script)
}

##########################
# Target Group
##########################
resource "aws_lb_target_group" "tg" {
  name     = "ACP-TG"
  port     = var.httpport
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200"
  }

  tags = { Name = "${local.name}-tg" }
}

resource "aws_lb_target_group_attachment" "tg_attach" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = var.httpport
}

##########################
# Application Load Balancer
##########################
resource "aws_lb" "lb" {
  name               = "lb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.pub_sn1.id, aws_subnet.pub_sn2.id]
  security_groups    = [aws_security_group.autocap_sg.id]
  internal           = false
  enable_deletion_protection = false

  # access_logs {
  #   bucket  = aws_s3_bucket.alb_log_bucket.id
  #   prefix  = "ACP-LB-LOG"
  #   enabled = true
  # }

  tags = { Name = "${local.name}-autocap_lb" }
}

resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = aws_lb.lb.arn
  port              = var.httpport
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

##########################
# AutoScaling Group
##########################
resource "aws_autoscaling_group" "asg" {
  name                      = "${local.name}-asg"
  max_size                  = 5
  min_size                  = 1
  desired_capacity          = 2
  vpc_zone_identifier       = [aws_subnet.pub_sn1.id, aws_subnet.pub_sn2.id]
  health_check_type         = "EC2"
  health_check_grace_period = 300
  force_delete              = true

  launch_template {
    id      = aws_launch_template.lnch_lt.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.tg.arn]

  tag {
    key                 = "Name"
    value               = "ASG"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "autoscaling_grp_policy" {
  name                   = "${local.name}-asg-policy"
  autoscaling_group_name = aws_autoscaling_group.asg.name
  policy_type            = "TargetTrackingScaling"
  adjustment_type        = "ChangeInCapacity"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 50.0
  }
}

##########################
# CloudFront Distribution
##########################
#creating aws_cloudfront_distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.autocap_media.bucket_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  # logging_config {
  #   include_cookies = false
  #   bucket          = "autocap-log-bucket.s3.amazonaws.com"
  #   prefix          = "cloudfront-log"
  # }
  logging_config {
  include_cookies = false
  bucket          = aws_s3_bucket.cloudfront_log_bucket.bucket_domain_name
  prefix          = "cloudfront/"
}


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
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

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # depends_on = [ null_resource.pre_scan ]

  tags = {
    Name = "${local.name}-cloudfront"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}

##########################
resource "aws_sns_topic" "server_alert" {
  name = "server-alert"
}

resource "aws_sns_topic_subscription" "acp_updates_sqs_target" {
  topic_arn = aws_sns_topic.server_alert.arn
  protocol  = "email"
  endpoint  = local.email
}

# ##########################
# CloudWatch Dashboards
# ##########################
#creating cloudwatch dashboard
resource "aws_cloudwatch_dashboard" "EC2_cloudwatch_dashboard" {
  dashboard_name = "EC2dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "${aws_instance.wordpress_server.id}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          region  = "eu-west-3"
          stacked = false
          stat    = "Average"
          title   = "EC2 Average CPUUtilization"
          view    = "timeSeries"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      }
    ]
  })
}

##########################
# CloudWatch Alarms
##########################
resource "aws_cloudwatch_metric_alarm" "CMA_EC2_Instance" {
  alarm_name          = "CMA-EC2"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_actions       = [aws_sns_topic.server_alert.arn]

  dimensions = { InstanceId = aws_instance.wordpress_server.id }
}

resource "aws_cloudwatch_metric_alarm" "CMA_ASG" {
  alarm_name          = "CMA-ASG"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_actions       = [aws_autoscaling_policy.autoscaling_grp_policy.arn, aws_sns_topic.server_alert.arn]

  dimensions = { AutoScalingGroupName = aws_autoscaling_group.asg.name }
}
