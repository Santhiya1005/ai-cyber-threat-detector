# -----------------
# Backend stage
# -----------------
FROM node:18 AS backend
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm install
COPY backend/ ./

# -----------------
# Frontend build stage
# -----------------
FROM node:18 AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./

# 🔹 Inject REACT_APP_API_URL at build time
ARG REACT_APP_API_URL
ENV REACT_APP_API_URL=$REACT_APP_API_URL

RUN npm run build

# -----------------
# AI service stage
# -----------------
FROM python:3.11-slim AS ai
WORKDIR /app/ai
COPY ai/requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt \
    && /opt/venv/bin/pip install uvicorn
ENV PATH="/opt/venv/bin:$PATH"
COPY ai/ ./

# -----------------
# Final stage
# -----------------
FROM node:18 AS final
WORKDIR /app

# Copy backend
COPY --from=backend /app/backend /app/backend

# Copy frontend build
COPY --from=frontend-build /app/frontend/build /app/frontend/build

# Copy AI app + Python venv
COPY --from=ai /app/ai /app/ai
COPY --from=ai /opt/venv /opt/venv

# Make venv available
ENV PATH="/opt/venv/bin:$PATH"

# Install tools
RUN npm install -g concurrently serve

# Expose all ports
EXPOSE 3000 4000 8000

# Run all 3 services in parallel
CMD ["concurrently", "-k", \
    "cd backend && npm start", \
    "cd frontend && serve -s build -l 3000", \
    "cd ai && uvicorn app:app --host 0.0.0.0 --port 8000"]
