# AI Cyber Threat Detector

## Project Overview
AI Cyber Threat Detector is a comprehensive full-stack application designed to identify and report cyber threats in real-time. It leverages machine learning to detect malicious files, suspicious IPs, and URLs. The system features an intuitive frontend dashboard for monitoring and reporting.

---

## Tech Stack
- **Frontend:** React.js  
- **Backend:** Node.js, Express.js  
- **AI/ML:** Python, TensorFlow / PyTorch  
- **Database:** MongoDB  
- **Containerization & Deployment:** Docker, Jenkins, Nginx  
- **Version Control:** Git & GitHub  

---

## Features
- Detect malicious files via hash analysis  
- Monitor suspicious IP addresses and URLs  
- Maintain a centralized database of threats  
- Real-time dashboard with threat statistics  
- Easy deployment using Docker and CI/CD pipelines  

---

## Directory Structure
cyber-threat-detector/
│
├─ ai/ # Python AI scripts and models
│ ├─ app.py
│ └─ dataset.json
│
├─ backend/ # Node.js backend
│ ├─ server.js
│ ├─ package.json
│ └─ venv/ # Python virtual environment (ignored in git)
│
├─ frontend/ # React.js frontend
│ ├─ public/
│ ├─ src/
│ └─ node_modules/ # Ignored in git
│
├─ Dockerfile
├─ .dockerignore
└─ README.md

yaml
Copy code

---

## Installation

### Backend
```bash
cd backend
python -m venv venv
# Activate virtual environment
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
pip install -r requirements.txt
Frontend
bash
Copy code
cd frontend
npm install
npm start
Docker
bash
Copy code
# Build Docker image
docker build -t cyber-threat-detector .

# Run Docker container
docker run -p 5000:5000 cyber-threat-detector
Git & Version Control
Initialize Git repo:

bash
Copy code
git init
Add .gitignore to ignore:

bash
Copy code
backend/venv/
frontend/node_modules/
.env
Stage and commit:

bash
Copy code
git add .
git commit -m "Initial commit"
Push to GitHub:

bash
Copy code
git remote add origin <your-repo-url>
git push -u origin main
Deployment Guide
Using Docker
Containerize backend & frontend

Expose required ports (e.g., 5000 for backend, 3000 for frontend)

Ensure environment variables (.env) are set inside container

Using Jenkins (CI/CD)
Create Jenkins pipeline for auto-deployment:

Pull code from GitHub

Build Docker images

Run containers on server

Using Nginx
Configure Nginx to serve frontend React app

Proxy API requests to backend container

Enable SSL using Certbot for HTTPS

Usage
Upload files or input suspicious IPs/URLs

AI model analyzes and returns threat status

View reports and statistics in dashboard

Notes
Do not commit .env or virtual environments (venv)

Large files (e.g., videos) should be ignored in .gitignore

Always test Docker container locally before deployment

