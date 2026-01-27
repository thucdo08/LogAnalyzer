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

- linuxsyslog
- windows_eventlog
- edr
- firewall
- router
- dns
- dhcp
- apache
- proxy
- ids

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
- Docker, Docker Compose, Jenkins, Nginx

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
