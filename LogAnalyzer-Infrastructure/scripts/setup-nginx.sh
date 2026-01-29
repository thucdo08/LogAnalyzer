#!/bin/bash
# setup-nginx.sh - Install and configure Nginx on Ubuntu 22.04

echo "=========================================="
echo "Installing Nginx and Certbot..."
echo "=========================================="

# Update packages
sudo apt-get update

# Install Nginx
sudo apt-get install -y nginx

# Install Certbot for SSL
sudo apt-get install -y certbot python3-certbot-nginx

# Create application directory
sudo mkdir -p /opt/loganalyzer
sudo chown -R ubuntu:ubuntu /opt/loganalyzer

# Create basic Nginx config for LogAnalyzer
cat <<'EOF' | sudo tee /etc/nginx/sites-available/loganalyzer
server {
    listen 80;
    server_name _;  # Will be updated with actual domain later
    
    # Frontend (will be served by Docker container on port 80)
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Backend API
    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeouts for AI processing
        proxy_read_timeout 300s;
        proxy_connect_timeout 300s;
    }
}
EOF

# Enable the site
sudo ln -sf /etc/nginx/sites-available/loganalyzer /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Start and enable Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
sudo systemctl reload nginx

echo ""
echo "=========================================="
echo "Nginx Installation Complete!"
echo "=========================================="
echo ""
echo "✅ Nginx installed and configured"
echo "🌐 Server IP: $(curl -s ifconfig.me)"
echo ""
echo "📝 Next steps:"
echo "1. Update DNS records to point your domain to this IP"
echo "2. Run: sudo certbot --nginx -d yourdomain.com"
echo "3. Deploy application containers"
