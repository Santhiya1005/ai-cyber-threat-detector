# Base image with Node
FROM node:18

# Install Python
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv

# Set workdir
WORKDIR /app

# --- Backend setup ---
COPY backend/package*.json ./backend/
RUN cd backend && npm install

# --- Frontend setup ---
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm install

# --- AI setup ---
COPY ai/requirements.txt ./ai/
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r ai/requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

# --- Copy all files ---
COPY . .

# --- Build frontend ---
RUN cd frontend && npm run build

# --- Install "concurrently" for multi-process ---
RUN npm install -g concurrently serve

# --- Expose ports ---
EXPOSE 4000 3000 8000

# --- Run backend + frontend + AI together ---
CMD concurrently \
  "cd backend && npm start" \
  "cd frontend && serve -s build -l 3000" \
  "cd ai && uvicorn app:app --host 0.0.0.0 --port 8000"
