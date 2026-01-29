output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "app_server_public_ip" {
  description = "Public IP of application server"
  value       = aws_eip.app_server.public_ip
}

output "jenkins_server_public_ip" {
  description = "Public IP of Jenkins server"
  value       = aws_eip.jenkins_server.public_ip
}

output "app_server_id" {
  description = "Instance ID of application server"
  value       = aws_instance.app_server.id
}

output "jenkins_server_id" {
  description = "Instance ID of Jenkins server"
  value       = aws_instance.jenkins_server.id
}

output "ssh_command_app" {
  description = "SSH command for application server"
  value       = "ssh -i ~/.ssh/loganalyzer-aws ubuntu@${aws_eip.app_server.public_ip}"
}

output "ssh_command_jenkins" {
  description = "SSH command for Jenkins server"
  value       = "ssh -i ~/.ssh/loganalyzer-aws ubuntu@${aws_eip.jenkins_server.public_ip}"
}

output "jenkins_url" {
  description = "Jenkins Web UI URL"
  value       = "http://${aws_eip.jenkins_server.public_ip}:8080"
}

output "app_url" {
  description = "Application URL (after setup)"
  value       = "http://${aws_eip.app_server.public_ip}"
}
