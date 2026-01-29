#!/bin/bash
# Configure Nginx reverse proxy for LogAnalyzer

echo "=== Configuring Nginx Reverse Proxy ==="

# Create Nginx configuration for LogAnalyzer
sudo tee /etc/nginx/sites-available/loganalyzer > /dev/null <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;

    # Frontend (React app on port 3000)
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API (Flask on port 8000)
    location /analyze {
        proxy_pass http://localhost:8000/analyze;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Allow large file uploads
        client_max_body_size 100M;
    }

    # Other API endpoints
    location /anomaly/ {
        proxy_pass http://localhost:8000/anomaly/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        client_max_body_size 100M;
    }
}
EOF

echo "✅ Created Nginx configuration"

# Remove default site
sudo rm -f /etc/nginx/sites-enabled/default

# Enable LogAnalyzer site
sudo ln -sf /etc/nginx/sites-available/loganalyzer /etc/nginx/sites-enabled/

echo "✅ Enabled LogAnalyzer site"

# Test Nginx configuration
echo "🧪 Testing Nginx configuration..."
sudo nginx -t

if [ $? -eq 0 ]; then
    echo "✅ Configuration valid"
    
    # Reload Nginx
    echo "🔄 Reloading Nginx..."
    sudo systemctl reload nginx
    
    echo "✅ Nginx reloaded successfully"
    echo ""
    echo "=== Deployment Complete ==="
    echo "Frontend: http://$(curl -s ifconfig.me)"
    echo "Backend API: http://$(curl -s ifconfig.me)/analyze"
else
    echo "❌ Configuration test failed"
    exit 1
fi
