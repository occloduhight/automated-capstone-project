output "wordpress_public_ip" {
  value = aws_instance.wordpress_server.public_ip
}
output "db-endpoint" {
  value = aws_db_instance.wordpress_db.endpoint
}