# LogAnalyzer Infrastructure

Infrastructure as Code for LogAnalyzer AI Security Platform deployment on AWS.

## 📦 Resources Created

- **VPC**: Custom VPC with public subnet
- **EC2 Instances**:
  - Application Server (t3.medium): 54.254.11.86
  - Jenkins Server (t3.small): 54.254.0.207
- **Security Groups**: Firewall rules for app and Jenkins
- **Elastic IPs**: Static IP addresses

## 🚀 Deployment

### Prerequisites

- Terraform >= 1.0
- AWS CLI configured
- SSH key pair created

### Deploy Infrastructure

```bash
cd terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

## 🔧 Server Setup

### 1. Setup Jenkins Server

```bash
# SSH into Jenkins server
ssh -i ~/.ssh/loganalyzer-aws ubuntu@54.254.0.207

# Install Docker
curl -O https://raw.githubusercontent.com/yourusername/LogAnalyzer-Infrastructure/main/scripts/install-docker.sh
chmod +x install-docker.sh
./install-docker.sh

# Install Jenkins
curl -O https://raw.githubusercontent.com/yourusername/LogAnalyzer-Infrastructure/main/scripts/install-jenkins.sh
chmod +x install-jenkins.sh
./install-jenkins.sh

# Exit and log back in for Docker group changes
exit
ssh -i ~/.ssh/loganalyzer-aws ubuntu@54.254.0.207
```

### 2. Setup Application Server

```bash
# SSH into app server
ssh -i ~/.ssh/loganalyzer-aws ubuntu@54.254.11.86

# Install Docker
curl -O https://raw.githubusercontent.com/yourusername/LogAnalyzer-Infrastructure/main/scripts/install-docker.sh
chmod +x install-docker.sh
./install-docker.sh

# Install Nginx
curl -O https://raw.githubusercontent.com/yourusername/LogAnalyzer-Infrastructure/main/scripts/setup-nginx.sh
chmod +x setup-nginx.sh
./setup-nginx.sh

# Exit and log back in
exit
```

## 🔐 Access

- **Jenkins**: http://54.254.0.207:8080
- **Application**: http://54.254.11.86 (after deployment)

## 💰 Cost Estimate

- t3.medium (App): ~$30/month
- t3.small (Jenkins): ~$15/month
- EIPs: ~$7/month
- **Total**: ~$57/month

## 🗑️ Cleanup

To destroy all resources and stop charges:

```bash
cd terraform
terraform destroy
```

## 📚 Documentation

- [AWS Deployment Plan](../aws_deployment_plan.md)
- [Step by Step Guide](../step_by_step_guide.md)

## 🏗️ Infrastructure Diagram

```
Internet
  │
  ├─→ App Server (54.254.11.86:80,443)
  │   └─→ Nginx → Docker Containers
  │       ├─→ Frontend (React)
  │       └─→ Backend (Flask)
  │
  └─→ Jenkins Server (54.254.0.207:8080)
      └─→ CI/CD Pipeline
```

## 🛠️ Tech Stack

- **IaC**: Terraform
- **Cloud**: AWS (VPC, EC2, Security Groups)
- **Container**: Docker
- **CI/CD**: Jenkins
- **Web Server**: Nginx
- **SSL**: Certbot/Let's Encrypt
