# LogAnalyze

## Overview

Fullstack application which allows you to analyze logs and detect security anomalies using AI-powered threat detection. The platform ingests logs from multiple sources, automatically identifies suspicious patterns through baseline comparison, and provides detailed AI-driven risk assessment.

## Prerequisites

You will need the following things properly installed on your computer.

- Node.js 18+
- Python 3.11+
- MongoDB Atlas or MongoDB 5+

Additionally, based on the backend and frontend implementations, you may need to install additional software.

## Database Setup

Locate the MongoDB connection and ensure you have a MongoDB instance running. For cloud setup, use MongoDB Atlas at https://www.mongodb.com/cloud/atlas

The database schema is automatically created when baselines are trained via the `/baseline/train` endpoint. No manual schema setup is required.

## Backend Setup

The backend is a Flask-based REST API that handles log processing, anomaly detection, and AI analysis.

**Installation:**

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

**Starting the Backend:**

```bash
python app.py
```

or using Uvicorn:

```bash
uvicorn app:app --reload --port 8000
```

Backend will be available at: `http://localhost:8000`

**Health Check:** `http://localhost:8000/health`

## Frontend Setup

The frontend is a React application built with Vite that provides a web interface for uploading logs, viewing analysis results, and managing baselines.

**Installation:**

```bash
cd frontend
npm install
```

**Starting the Frontend (Development):**

```bash
npm run dev
```

Frontend will be available at: `http://localhost:5173`

**Building for Production:**

```bash
npm run build
```

## Running Backend and Frontend

(1) Follow instructions for setting up the backend implementation and starting it:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate  # Windows or: source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python app.py
```

Backend will be available at: `http://localhost:8000`

(2) Follow instructions for setting up the frontend implementation and starting it (open a new terminal):

```bash
cd frontend
npm install
npm run dev
```

Frontend will be available at: `http://localhost:5173`

(3) Alternatively, follow instructions for starting up Docker containers using Docker Compose:

```bash
docker-compose up -d
```

- Frontend: http://localhost
- Backend API: http://localhost:8000

(4) Once the backend and frontend are running, open your browser and goto: `http://localhost:5173`

## Project Structure

```
LogAnalyze/
├── backend/                      # Flask REST API
│   ├── app.py                   # Main application
│   ├── requirements.txt         # Python dependencies
│   ├── Dockerfile              # Docker configuration
│   ├── config/                  # Configuration files
│   │   ├── rules.json
│   │   ├── scoring.json
│   │   └── baselines/
│   ├── services/                # Business logic
│   │   ├── analyzer.py
│   │   ├── anomaly.py
│   │   ├── baseline.py
│   │   ├── preprocess.py
│   │   ├── postprocess.py
│   │   ├── database.py
│   │   ├── alert.py
│   │   ├── enrich.py
│   │   ├── filters.py
│   │   ├── scoring.py
│   │   └── validator.py
│   └── utils/                   # Utility modules
│       ├── file_handler.py
│       └── syslog_parser.py
├── frontend/                     # React web application
│   ├── src/
│   │   ├── App.jsx             # Main component
│   │   ├── App.css             # Styles
│   │   ├── index.css           # Global styles
│   │   ├── main.jsx            # Entry point
│   │   └── assets/
│   ├── package.json            # JavaScript dependencies
│   ├── vite.config.js          # Vite configuration
│   ├── Dockerfile              # Docker configuration
│   ├── nginx.conf              # Nginx configuration
│   ├── eslint.config.js        # ESLint configuration
│   └── public/
├── LogAnalyzer-Infrastructure/  # AWS IaC deployment
│   ├── terraform/               # Terraform configurations
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── vpc.tf
│   │   ├── security-groups.tf
│   │   ├── ec2.tf
│   │   └── outputs.tf
│   ├── scripts/                 # Deployment scripts
│   │   ├── install-docker.sh
│   │   ├── install-jenkins.sh
│   │   └── configure-nginx.sh
│   ├── docs/                    # Deployment documentation
│   │   ├── AWS_Deployment_Plan.md
│   │   ├── Step_by_Step_Guide.md
│   │   └── AWS_Cleanup_Guide.md
│   └── README.md
├── docker-compose.yml          # Docker Compose configuration
├── Jenkinsfile                 # CI/CD pipeline
└── README.md                   # This file
```

## Key Features

- **Multi-Format Log Support**: Parse logs from Linux syslog, Windows Event Logs, firewalls, routers, DNS, Apache, and more
- **Baseline-Driven Anomaly Detection**: Automatic detection based on historical baseline models
- **AI-Powered Analysis**: GPT-4 powered threat assessment and risk analysis
- **Group-Based Baseline**: Support for departmental/team-level analysis
- **Real-Time Alerting**: Notifications via N8N, Telegram, and Zalo
- **MongoDB Integration**: Persistent storage of baselines and analysis results
- **Docker Support**: Complete containerization for easy deployment

## Supported Log Types

- apache
- dhcp
- dns
- edr
- firewall
- linuxsyslog
- router
- windows_eventlog


## API Endpoints

**Analysis:**
- `POST /analyze` - Complete pipeline analysis
- `POST /anomaly/raw` - Generate raw anomaly alerts
- `POST /anomaly/prompt` - AI analysis of alerts
- `POST /anomaly/batch-analyze` - Batch process alerts

**Baseline Management:**
- `POST /baseline/train` - Train baseline models
- `GET /baseline/status` - Check baseline status
- `GET /baseline/members` - View group memberships

**Health & Status:**
- `GET /health` - Health check
- `GET /ai/status` - Check AI API status
- `GET /api/health/mongodb` - Check MongoDB connection

**Alerting:**
- `POST /send-analysis-alerts` - Send analyzed alerts
- `POST /send-raw-anomalies` - Send raw anomaly alerts
- `POST /send-telegram` - Send Telegram notification
- `POST /send-zalo` - Send Zalo notification

## Tech Stack

**Backend:**
- Flask, Pandas, NumPy, MongoDB, OpenAI API, scikit-learn, Uvicorn

**Frontend:**
- React 19, Vite, PrimeReact, Tailwind CSS, ESLint

**Infrastructure:**
- Docker, Docker Compose, Jenkins, Nginx, Terraform, AWS

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Commit and push
5. Create a Pull Request

## Support

For additional help and documentation:
- Review the API endpoint specifications in Backend Setup
- Check configuration options in the Project Structure section
- Review Dockerfile for containerization details

---

## AWS Infrastructure as Code Deployment

This project includes complete AWS deployment using Infrastructure as Code (Terraform) with automated CI/CD pipeline.

### 🏗️ Infrastructure Overview

**Deployed Resources:**
- **VPC**: Custom VPC (10.0.0.0/16) with public subnet
- **EC2 Instances**: 
  - Application Server (t3.medium) - Hosts Docker containers
  - Jenkins Server (t3.small) - CI/CD automation
- **Security Groups**: Firewall rules for app and Jenkins servers
- **Elastic IPs**: Static IP addresses for both servers
- **Nginx**: Reverse proxy with SSL/TLS support
- **Let's Encrypt**: Automated SSL certificate management

**Monthly Cost**: ~$57 (when running)

### 🚀 Quick Deployment

```bash
# 1. Configure AWS credentials
aws configure

# 2. Navigate to infrastructure directory
cd LogAnalyzer-Infrastructure/terraform

# 3. Initialize Terraform
terraform init

# 4. Deploy infrastructure
terraform apply

# 5. Follow post-deployment setup
# See: LogAnalyzer-Infrastructure/docs/Step_by_Step_Guide.md
```

### 🔄 CI/CD Pipeline

Automated deployment pipeline using Jenkins:

1. **Code Push** → GitHub (main branch)
2. **Webhook Trigger** → Jenkins auto-build
3. **Build Images** → Docker (frontend + backend)
4. **Push to Registry** → Docker Hub
5. **Deploy** → SSH to App Server
6. **Start Containers** → docker-compose up -d
7. **Health Check** → Verify deployment

**Pipeline Configuration**: [`Jenkinsfile`](Jenkinsfile)

### 📦 Published Docker Images

- **Backend**: [dhuuthuc/loganalyze-backend:latest](https://hub.docker.com/r/dhuuthuc/loganalyze-backend)
- **Frontend**: [dhuuthuc/loganalyze-frontend:latest](https://hub.docker.com/r/dhuuthuc/loganalyze-frontend)

### 📚 Infrastructure Documentation

Comprehensive guides available in [`LogAnalyzer-Infrastructure/docs/`](LogAnalyzer-Infrastructure/docs/):

- **[AWS Deployment Plan](LogAnalyzer-Infrastructure/docs/AWS_Deployment_Plan.md)** - Complete deployment strategy
- **[Step-by-Step Guide](LogAnalyzer-Infrastructure/docs/Step_by_Step_Guide.md)** - Detailed deployment instructions (all 6 phases)
- **[AWS Cleanup Guide](LogAnalyzer-Infrastructure/docs/AWS_Cleanup_Guide.md)** - Resource deletion and cost management

### 🏛️ Infrastructure Diagram

```
                    AWS Cloud (ap-southeast-1)
    ┌───────────────────────────────────────────────────┐
    │                VPC: 10.0.0.0/16                   │
    │  ┌─────────────────────────────────────────────┐  │
    │  │      Public Subnet: 10.0.1.0/24             │  │
    │  │                                             │  │
    │  │  ┌─────────────┐    ┌──────────────────┐   │  │
    │  │  │  Jenkins    │    │  App Server      │   │  │
    │  │  │  Server     │SSH │  + Nginx         │   │  │
    │  │  │  (t3.small) │───►│  + Docker        │   │  │
    │  │  │             │    │    - Frontend    │   │  │
    │  │  │  CI/CD      │    │    - Backend     │   │  │
    │  │  └─────────────┘    └──────────────────┘   │  │
    │  │         │                     │            │  │
    │  │    Elastic IP           Elastic IP         │  │
    │  └─────────┼─────────────────────┼────────────┘  │
    │            │                     │               │
    │      Security Groups      Security Groups        │
    │      (SSH, 8080)         (SSH, HTTP, HTTPS)      │
    └────────────┼─────────────────────┼───────────────┘
                 │                     │
                 ▼                     ▼
          Jenkins Admin          End Users
        (Pipeline Mgmt)      (Web Application)
```

### 🗑️ Resource Cleanup

To destroy all AWS resources and stop charges:

```bash
cd LogAnalyzer-Infrastructure/terraform
terraform destroy
```

**Savings**: ~$57/month

> **Note**: Production deployment was taken offline after demonstration to minimize costs. All infrastructure code, Docker images, and documentation are preserved for redeployment.
