# LogAnalyze

## Overview

Fullstack application which allows you to analyze logs and detect security anomalies using AI-powered threat detection. The platform ingests logs from multiple sources, automatically identifies suspicious patterns through baseline comparison, and provides detailed AI-driven risk assessment.

## Prerequisites

You will need the following things properly installed on your computer.

- Node.js 18+
- Python 3.11+
- MongoDB Atlas or MongoDB 5+

Additionally, based on the backend and frontend implementations, you may need to install additional software. Please see their README's for more info.

## Database Setup

Locate the MongoDB connection and ensure you have a MongoDB instance running. For cloud setup, use MongoDB Atlas at https://www.mongodb.com/cloud/atlas

The database schema is automatically created when baselines are trained via the `/baseline/train` endpoint. No manual schema setup is required.

## Backend Setup

This project has Flask-based backend implementation which is designed to handle log processing, anomaly detection, and AI analysis.

Please choose any of the following implementations and setup as guided in their README's.

- **Flask Backend** (backend)

Setup instructions can be found in `backend/README.md`

## Frontend Setup

This project has a React-based frontend implementation which provides a web interface for the log analysis platform.

Please choose any of the following implementations and setup as guided in their README's.

- **React Frontend** (frontend)

Setup instructions can be found in `frontend/README.md`

## Running Backend and Frontend

(1) Follow instructions for setting up the backend implementation and starting it. They can be found in `backend/README.md`

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate  # Windows or: source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python app.py
```

Backend will be available at: `http://localhost:8000`

(2) Follow instructions for setting up the frontend implementation and starting it. They can be found in `frontend/README.md`

Open a new terminal:
```bash
cd frontend
npm install
npm run dev
```

Frontend will be available at: `http://localhost:5173`

(3) Alternatively, follow instructions for starting up Docker containers using Docker Compose found in the root `docker-compose.yml`:

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
│   │   └── ...
│   └── utils/                   # Utility modules
├── frontend/                     # React web application
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   ├── vite.config.js
│   └── public/
├── docker-compose.yml           # Docker Compose configuration
└── Jenkinsfile                  # CI/CD pipeline
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
- POST /analyze
- POST /anomaly/raw
- POST /anomaly/prompt
- POST /anomaly/batch-analyze

**Baseline Management:**
- POST /baseline/train
- GET /baseline/status
- GET /baseline/members

**Health & Status:**
- GET /health
- GET /ai/status
- GET /api/health/mongodb

## Tech Stack

**Backend:**
- Flask, Pandas, NumPy, MongoDB, OpenAI API, scikit-learn

**Frontend:**
- React 19, Vite, PrimeReact, Tailwind CSS

**Infrastructure:**
- Docker, Docker Compose, Jenkins

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Commit and push
5. Create a Pull Request

## Support

For detailed documentation on specific components:
- Backend: `backend/README.md`
- Frontend: `frontend/README.md`
