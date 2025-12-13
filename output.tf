output "wordpress_instance_public_ip" {
  value       = aws_instance.wordpress_server.public_ip
  description = "The public IP of the WordPress EC2 instance"
}
output "alb_dns_name" {
  value = aws_lb.lb.dns_name
}
