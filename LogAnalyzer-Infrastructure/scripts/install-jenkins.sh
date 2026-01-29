#!/bin/bash
# install-jenkins.sh - Install Jenkins on Ubuntu 22.04

echo "=========================================="
echo "Installing Jenkins..."
echo "=========================================="

# Install Java (required for Jenkins)
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk

# Add Jenkins GPG key
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | sudo tee \
  /usr/share/keyrings/jenkins-keyring.asc > /dev/null

# Add Jenkins repository
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null

# Install Jenkins
sudo apt-get update
sudo apt-get install -y jenkins

# Start and enable Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins

# Add jenkins user to docker group (if Docker is installed)
if groups jenkins | grep -q docker; then
    echo "Jenkins user already in docker group"
else
    sudo usermod -aG docker jenkins
    sudo systemctl restart jenkins
fi

# Wait for Jenkins to start
echo "Waiting for Jenkins to start..."
sleep 15

# Get initial admin password
echo ""
echo "=========================================="
echo "Jenkins Installation Complete!"
echo "=========================================="
echo ""
echo "🔑 Jenkins Initial Admin Password:"
echo "=========================================="
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
echo "=========================================="
echo ""
echo "✅ Jenkins installed successfully!"
echo "🌐 Access Jenkins at: http://$(curl -s ifconfig.me):8080"
echo ""
echo "📝 Next steps:"
echo "1. Open Jenkins URL in browser"
echo "2. Enter the initial admin password above"
echo "3. Install suggested plugins"
echo "4. Create admin user"
