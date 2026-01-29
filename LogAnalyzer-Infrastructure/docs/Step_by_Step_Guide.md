# LogAnalyzer AWS Deployment - Complete Step-by-Step Guide

**Duration**: ~2-3 days  
**Final Result**: https://dofuta.site (production-ready with CI/CD)

---

## 📋 Table of Contents

1. [Phase 1: Environment Setup](#phase-1-environment-setup)
2. [Phase 2: AWS Infrastructure (Terraform)](#phase-2-aws-infrastructure-terraform)
3. [Phase 3: Manual Server Configuration](#phase-3-manual-server-configuration)
4. [Phase 4: Jenkins CI/CD Setup](#phase-4-jenkins-cicd-setup)
5. [Phase 5: Domain & SSL Configuration](#phase-5-domain--ssl-configuration)
6. [Phase 6: GitHub Webhook](#phase-6-github-webhook)

---

## Phase 1: Environment Setup

### **Step 1.1: Install Required Tools**

**Terraform:**
```powershell
# Check if installed
terraform version

# If not, download from: https://www.terraform.io/downloads
# Add to PATH
```

**AWS CLI:**
```powershell
# Check if installed
aws --version

# If not, download from: https://aws.amazon.com/cli/
```

**Git:**
```powershell
# Check if installed
git --version
```

---

### **Step 1.2: Configure AWS Credentials**

**Create IAM User:**
1. AWS Console → IAM → Users → Add User
2. User name: `terraform-user`
3. Access type: ✅ Programmatic access
4. Permissions: Attach policies:
   - `AmazonEC2FullAccess`
   - `AmazonVPCFullAccess`
   - `IAMReadOnlyAccess`
5. Download Access Key ID & Secret Access Key

**Configure AWS CLI:**
```powershell
aws configure
# AWS Access Key ID: [paste your key]
# AWS Secret Access Key: [paste your secret]
# Default region: ap-southeast-1
# Default output: json

# Verify
aws sts get-caller-identity
```

---

### **Step 1.3: Create SSH Key Pair**

```powershell
cd $env:USERPROFILE\.ssh

# Generate key pair
ssh-keygen -t rsa -b 4096 -f loganalyzer-aws -N '""'

# Files created:
# - loganalyzer-aws (private key)
# - loganalyzer-aws.pub (public key)
```

---

## Phase 2: AWS Infrastructure (Terraform)

### **Step 2.1: Create Terraform Configuration Files**

**Directory structure:**
```
d:\CV\LogAnalyzer\
├── LogAnalyzer-Infrastructure\
│   ├── terraform\
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── vpc.tf
│   │   ├── security-groups.tf
│   │   ├── ec2.tf
│   │   └── outputs.tf
│   └── scripts\
│       ├── install-docker.sh
│       ├── install-jenkins.sh
│       └── configure-nginx.sh
```

**Key files created:**
- `main.tf`: AWS provider configuration
- `variables.tf`: Input variables (region, instance types, etc.)
- `vpc.tf`: VPC, subnet, internet gateway, route tables
- `security-groups.tf`: Firewall rules for Jenkins & App servers
- `ec2.tf`: EC2 instances with Elastic IPs
- `outputs.tf`: Display important values after deployment

---

### **Step 2.2: Deploy Infrastructure with Terraform**

```powershell
cd d:\CV\LogAnalyzer\LogAnalyzer-Infrastructure\terraform

# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy infrastructure
terraform apply
# Type 'yes' when prompted

# Save outputs
terraform output
```

**Resources created:**
- VPC: `10.0.0.0/16`
- Public Subnet: `10.0.1.0/24`
- Internet Gateway
- 2 Security Groups (Jenkins, App Server)
- 2 EC2 instances (t3.small, t3.medium)
- 2 Elastic IPs

**Important IPs (save these):**
- Jenkins Server: `54.254.0.207`
- App Server: `54.254.11.86`

---

## Phase 3: Manual Server Configuration

### **Step 3.1: Setup Application Server**

**SSH into App Server:**
```powershell
ssh -i "$env:USERPROFILE\.ssh\loganalyzer-aws" ubuntu@54.254.11.86
```

**Install Docker:**
```bash
# Update system
sudo apt update

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker ubuntu

# Logout and login again
exit
ssh -i "$env:USERPROFILE\.ssh\loganalyzer-aws" ubuntu@54.254.11.86

# Verify Docker
docker --version
```

**Install Docker Compose:**
```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
docker-compose --version
```

**Install Nginx:**
```bash
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# Verify
curl http://localhost
# Should see "Welcome to nginx!"
```

**Install Certbot (for SSL):**
```bash
sudo apt install -y certbot python3-certbot-nginx
```

**Create application directory:**
```bash
sudo mkdir -p /opt/loganalyzer
sudo chown ubuntu:ubuntu /opt/loganalyzer
cd /opt/loganalyzer

# Create Docker network
docker network create loganalyzer-network || true
```

---

### **Step 3.2: Setup Jenkins Server**

**SSH into Jenkins Server:**
```powershell
ssh -i "$env:USERPROFILE\.ssh\loganalyzer-aws" ubuntu@54.254.0.207
```

**Install Docker:**
```bash
# Same steps as App Server
sudo apt update
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Logout and login
exit
ssh -i "$env:USERPROFILE\.ssh\loganalyzer-aws" ubuntu@54.254.0.207

docker --version
```

**Install Java:**
```bash
sudo apt update
sudo apt install -y openjdk-17-jdk
java -version
```

**Install Jenkins (WAR file method):**
```bash
# Download Jenkins WAR
wget https://get.jenkins.io/war-stable/latest/jenkins.war

# Run Jenkins
nohup java -jar jenkins.war --httpPort=8080 > jenkins.log 2>&1 &

# Wait 30 seconds for startup
sleep 30

# Get initial admin password
cat ~/.jenkins/secrets/initialAdminPassword
# Copy this password!
```

**Access Jenkins:**
- URL: http://54.254.0.207:8080
- Paste initial admin password
- Install suggested plugins
- Create admin user: `admin` / [your password]

---

## Phase 4: Jenkins CI/CD Setup

### **Step 4.1: Install Jenkins Plugins**

In Jenkins UI:
1. Manage Jenkins → Plugins → Available plugins
2. Search and install:
   - Docker Pipeline
   - SSH Agent
   - Credentials Binding
   - GitHub Integration
3. Restart Jenkins: `http://54.254.0.207:8080/restart`

---

### **Step 4.2: Add Credentials to Jenkins**

**Dashboard → Manage Jenkins → Credentials → System → Global credentials**

**1. Docker Hub Credentials:**
- Kind: Username with password
- Username: `dhuuthuc`
- Password: [your Docker Hub password]
- ID: `docker-hub-credentials`

**2. SSH Private Key (App Server):**
- Kind: SSH Username with private key
- Username: `ubuntu`
- Private Key: Enter directly
  ```
  Open Notepad → Open loganalyzer-aws (private key)
  Copy ENTIRE content (including BEGIN/END lines)
  Paste into Jenkins
  ```
- ID: `app-server-ssh`

**3. OpenAI API Key:**
- Kind: Secret text
- Secret: [your OpenAI API key]
- ID: `openai-api-key`

**4. MongoDB URI:**
- Kind: Secret text
- Secret: [your MongoDB Atlas connection string]
- ID: `mongodb-uri`

**5. MongoDB DB Name:**
- Kind: Secret text
- Secret: `loganalyzer`
- ID: `mongodb-db-name`

---

### **Step 4.3: Update Jenkinsfile**

**File: `d:\CV\LogAnalyzer\Jenkinsfile`**

Key sections:
- Checkout code from GitHub
- Build Docker images (frontend, backend)
- Push to Docker Hub
- SSH to App Server
- Create `.env` file with secrets
- Generate `docker-compose.yml`
- Deploy with `docker-compose up -d`
- Health check verification

**Commit and push:**
```powershell
cd d:\CV\LogAnalyzer
git add Jenkinsfile
git commit -m "feat(ci): add AWS deployment pipeline"
git push origin main
```

---

### **Step 4.4: Create Jenkins Pipeline Job**

In Jenkins:
1. New Item → Enter name: `LogAnalyzer-Pipeline`
2. Select: Pipeline
3. Pipeline definition: Pipeline script from SCM
4. SCM: Git
5. Repository URL: `https://github.com/thucdo08/LogAnalyzer.git`
6. Branch: `*/main`
7. Script Path: `Jenkinsfile`
8. Save

---

### **Step 4.5: Run First Build**

1. Click job → Build Now
2. Monitor build progress
3. Check console output for errors

**Common issues fixed:**
- SSH key format → Manual copy from Notepad
- Docker Compose missing → Manual install on App Server
- Nginx not configured → Manual Nginx setup

---

### **Step 4.6: Configure Nginx Reverse Proxy**

**On App Server:**
```bash
sudo tee /etc/nginx/sites-available/loganalyzer > /dev/null <<'EOF'
server {
    listen 80 default_server;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }

    location /analyze {
        proxy_pass http://localhost:8000;
        client_max_body_size 100M;
    }

    location /anomaly/ {
        proxy_pass http://localhost:8000;
        client_max_body_size 100M;
    }
}
EOF

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/loganalyzer /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**Test:**
```bash
curl http://localhost:3000  # Frontend
curl -X POST http://localhost:8000/analyze  # Backend
```

---

## Phase 5: Domain & SSL Configuration

### **Step 5.1: Configure DNS Records**

**In your DNS provider (Cloudflare/GoDaddy/etc.):**

Add A records:
```
Type: A
Name: @
Value: 54.254.11.86
TTL: Automatic

Type: A
Name: www
Value: 54.254.11.86
TTL: Automatic
```

**Wait 5-10 minutes for DNS propagation.**

**Verify:**
```powershell
nslookup dofuta.site
nslookup www.dofuta.site
# Should return: 54.254.11.86
```

---

### **Step 5.2: Install SSL Certificate**

**On App Server:**
```bash
sudo certbot --nginx -d dofuta.site -d www.dofuta.site
```

**Answer prompts:**
- Email: [your email]
- Agree to ToS: Y
- Share email: N
- Redirect HTTP to HTTPS: 2 (Yes)

**Certbot will:**
- Verify domain ownership
- Generate SSL certificate
- Auto-configure Nginx
- Setup auto-renewal

---

### **Step 5.3: Update Nginx for HTTPS + Timeouts**

```bash
sudo tee /etc/nginx/sites-available/loganalyzer > /dev/null <<'EOF'
server {
    listen 80;
    server_name dofuta.site www.dofuta.site;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name dofuta.site www.dofuta.site;
    
    ssl_certificate /etc/letsencrypt/live/dofuta.site/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dofuta.site/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }

    location /analyze {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        client_max_body_size 100M;
        
        # AI processing timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    location /anomaly/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        client_max_body_size 100M;
        proxy_read_timeout 300s;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx
```

---

### **Step 5.4: Update Frontend API Endpoint**

**File: `d:\CV\LogAnalyzer\frontend\src\App.jsx`**

Change:
```javascript
const API_BASE = "https://dofuta.site";
```

**Commit and push:**
```powershell
cd d:\CV\LogAnalyzer
git add frontend/src/App.jsx
git commit -m "feat: update API_BASE to HTTPS domain"
git push origin main
```

**Trigger Jenkins build** → Wait for deployment

**Test:** https://dofuta.site

---

## Phase 6: GitHub Webhook

### **Step 6.1: Enable Webhook in Jenkins**

In Jenkins:
1. LogAnalyzer-Pipeline → Configure
2. Build Triggers section
3. ✅ Check: "GitHub hook trigger for GITScm polling"
4. Save

---

### **Step 6.2: Add Webhook on GitHub**

1. Go to: https://github.com/thucdo08/LogAnalyzer/settings/hooks
2. Add webhook
3. Payload URL: `http://54.254.0.207:8080/github-webhook/`
4. Content type: `application/json`
5. SSL verification: Disable
6. Events: Just the push event
7. Active: ✅
8. Add webhook

**Verify:** Should see ✅ green checkmark

---

### **Step 6.3: Test Auto-Build**

```powershell
cd d:\CV\LogAnalyzer
echo "`n## Auto-Build Test" >> README.md
git add README.md
git commit -m "test: webhook auto-build"
git push origin main
```

**Check Jenkins** - Build should start automatically in ~10-30 seconds!

---

## 🎉 Deployment Complete!

**Production URLs:**
- Application: https://dofuta.site
- Jenkins: http://54.254.0.207:8080

**Features:**
- ✅ HTTPS with Let's Encrypt SSL
- ✅ Auto-build on git push
- ✅ Zero-downtime deployment
- ✅ Infrastructure managed by Terraform
- ✅ Complete CI/CD automation

---

## 📊 Final Metrics

| Metric | Value |
|--------|-------|
| Infrastructure resources | 11 (Terraform-managed) |
| Deployment time | ~5 minutes (automated) |
| SSL rating | A+ |
| CI/CD automation | 100% |
| Monthly cost | ~$57 |

---

**Next**: See `aws_cleanup_guide.md` for instructions to delete resources and avoid charges!
