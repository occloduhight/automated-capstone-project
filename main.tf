locals {
  name = "autocap"
  email = "chinweodochi@gmail.com"
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

# Creating log bucket
resource "aws_s3_bucket" "autocap_log_bucket" {
  bucket        = "autocap-log-bucket"
  depends_on    = [null_resource.pre_scan]
  force_destroy = true

  tags = {
    Name = "${local.name}-autocap-log-bucket"
  }
}

# Disable S3 Block Public Access BEFORE applying policy
resource "aws_s3_bucket_public_access_block" "log_bucket_access_block" {
  bucket = aws_s3_bucket.autocap_log_bucket.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# Ownership controls
resource "aws_s3_bucket_ownership_controls" "log_bucket_owner" {
  bucket = aws_s3_bucket.autocap_log_bucket.id

  depends_on = [
    aws_s3_bucket_public_access_block.log_bucket_access_block
  ]

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# ACL (must come AFTER ownership controls)
resource "aws_s3_bucket_acl" "log_bucket_acl" {
  bucket = aws_s3_bucket.autocap_log_bucket.id

  depends_on = [
    aws_s3_bucket_ownership_controls.log_bucket_owner
  ]

  acl = "private"
}

# Log bucket policy document
data "aws_iam_policy_document" "log-bucket-access-policy" {
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
      "${aws_s3_bucket.autocap_log_bucket.arn}/*",
    ]
  }
}

# Bucket policy (must depend on public access block)
resource "aws_s3_bucket_policy" "autocap-log-bucket-policy" {
  bucket = aws_s3_bucket.autocap_log_bucket.id
  policy = data.aws_iam_policy_document.log-bucket-access-policy.json

  depends_on = [
    aws_s3_bucket_public_access_block.log_bucket_access_block
  ]
}
# DB Subnet Group
resource "aws_db_subnet_group" "database" {
  name       = "database"
  subnet_ids = [aws_subnet.prv_sn1.id, aws_subnet.prv_sn2.id]

  tags = {
    Name = "${local.name}-db-subnet"
  }
}
# creating DB subnet 
resource "aws_db_subnet_group" "database" {
  name       = "database"
  subnet_ids = [aws_subnet.prv_sn1.id, aws_subnet.prv_sn2.id]

  tags = {
    Name = "${local.name}-db-subnet"
  }
}

# creating RDS
resource "aws_db_instance" "wordpress-db" {
  identifier             = var.db_identifier
  db_subnet_group_name   = aws_db_subnet_group.database.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  allocated_storage      = 10
  db_name                = var.dbname
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = local.db-cred.username
  password               = local.db-cred.password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}
resource "aws_ami_from_instance" "asg_ami" {
  name                    = "asg-ami"
  source_instance_id      = aws_instance.wordpress_server.id
  snapshot_without_reboot = true
  depends_on              = [aws_instance.wordpress_server, time_sleep.ami-sleep]

}

resource "time_sleep" "ami-sleep" {
  depends_on      = [aws_instance.wordpress_server]
  create_duration = "360s"

}

#creating aws_cloudfront_distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.autocap_media.bucket_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  logging_config {
    include_cookies = false
    bucket          = "autocap-log-bucket.s3.amazonaws.com"
    prefix          = "cloudfront-log"
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

  depends_on = [ null_resource.pre_scan ]

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

# Creating Instance
resource "aws_instance" "wordpress_server" {
  ami           = var.redhat_ami
  instance_type = var.instance_type
  depends_on = [ null_resource.pre_scan ]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.autocap_sg.id, aws_security_group.rds_sg.id]
  subnet_id                   = aws_subnet.pub_sn1.id
  iam_instance_profile        = aws_iam_instance_profile.iam_instance_profile.id
  key_name                    = aws_key_pair.key.id
   user_data                   = local.wordpress_script
   
  tags = {
    Name = "${local.name}-wordpress_server"
  }
}

 #creating ACM certificate
resource "aws_acm_certificate" "acm-cert" {
  domain_name       = "greatminds.sbs"
  validation_method = "DNS"

  tags = {
    Name = "${local.name}-acm-cert"
  }
}
 
 #creating route53 hosted zone
 data "aws_route53_zone" "autocap-zone" {
   name         = var.domain
   private_zone = false
 }

 #creating A record
 resource "aws_route53_record" "autocap-record" {
   zone_id = data.aws_route53_zone.autocap-zone.zone_id
   name    = var.domain
   type    = "A"
   alias {
    name                   = aws_lb.lb.dns_name
     zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = true
   }
 }
 
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
resource "aws_cloudwatch_dashboard" "asg_cpu_utilization_dashboard" {
  dashboard_name = "asgcpuutilizationdashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "${aws_autoscaling_group.asg.id}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          view    = "timeSeries"
          stat    = "Average"
          stacked = false
          region  = "eu-west-3"
          title   = "Average CPU Utilization"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      },
    ]
  })
}

// Creating cloudwatch metric alarm ec2 instance
resource "aws_cloudwatch_metric_alarm" "CMA_EC2_Instance" {
  alarm_name          = "CMA-Instance"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.server_alert.arn]
  dimensions = {
    InstanceId : aws_instance.wordpress_server.id
  }
}
// Creating cloudwatch metric alarm auto-scalling group
resource "aws_cloudwatch_metric_alarm" "CMA_Autoscaling_Group" {
  alarm_name          = "CMA-asg"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric monitors asg cpu utilization"
  alarm_actions       = [aws_autoscaling_policy.autoscaling_grp-policy.arn, aws_sns_topic.server_alert.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
}

#creating sns topic
resource "aws_sns_topic" "server_alert" {
  name            = "server-alert"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}
#creating sns topic subscription
resource "aws_sns_topic_subscription" "acp_updates_sqs_target" {
  topic_arn = aws_sns_topic.server_alert.arn
  protocol  = "email"
  endpoint  = local.email
}

# Creating launch configuration
resource "aws_launch_configuration" "lnch_lt" {
  name                        = "${local.name}-web_config"
  image_id                    = aws_ami_from_instance.asg_ami.id
  instance_type               = var.instance_type
  iam_instance_profile        = aws_iam_instance_profile.iam_instance_profile.id
  security_groups             = [aws_security_group.ACP-SG.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.key.id
  user_data                   = local.wordpress_script

}

# creating autoscaling group
resource "aws_autoscaling_group" "autoscaling_grp" {
  name                      = "${local.name}-asg"
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  desired_capacity          = 2
  force_delete              = true
  launch_configuration      = aws_launch_configuration.lnch_lt.id
  vpc_zone_identifier       = [aws_subnet.pub_sn1.id, aws_subnet.pub_sn2.id]
  target_group_arns         = [aws_lb_target_group.tg.arn]

  tag {
    key                 = "Name"
    value               = "ASG"
    propagate_at_launch = true
  }
}

# creating autoscaling policy
resource "aws_autoscaling_policy" "autoscaling_grp-policy" {
  autoscaling_group_name = aws_autoscaling_group.autoscaling_grp.name
  name                   = "$(local.name)-asg-policy"
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    target_value = 50.0
  }
}

# creating target group
resource "aws_lb_target_group" "tg" {
  name     = "ACP-TG"
  port     = var.httpport
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    interval            = 60
    port                = 80
    timeout             = 30
    path                = "/indextest.html"
    protocol            = "HTTP"
  }
}

# creating target group listener
resource "aws_lb_target_group_attachment" "tg-attach" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = var.httpport
}

# creating load balancer
resource "aws_lb" "lb" {
  name                       = "autocap_lb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.autocap_sg.id]
  subnets                    = [aws_subnet.pub_sn1.id, aws_subnet.pub_sn2.id]
  enable_deletion_protection = false
  access_logs {
    bucket  = aws_s3_bucket.autocap_log_bucket.id
    prefix  = "ACP-LB-LOG"
    enabled = true
  }
  tags = {
    Name = "${local.name}-autocap_lb"
  }
}

# creating load balancer listener
resource "aws_lb_listener" "LB-listener" {
  load_balancer_arn = aws_lb.lb.arn
  port              = var.httpport
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}





