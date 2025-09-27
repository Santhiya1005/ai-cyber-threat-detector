FROM node:18-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM node:18-slim AS backend
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm install
COPY backend/ ./

FROM python:3.11-slim AS ai
WORKDIR /app/ai
COPY ai/requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt
ENV PATH="/opt/venv/bin:$PATH"
COPY ai/ ./

FROM node:18-slim
WORKDIR /app
COPY --from=backend /app/backend /app/backend
COPY --from=frontend-build /app/frontend/build /app/frontend/build
COPY --from=ai /app/ai /app/ai
ENV PATH="/opt/venv/bin:$PATH"

RUN npm install -g concurrently serve

EXPOSE 4000 3000 8000

CMD concurrently \
  "cd backend && npm start" \
  "serve -s frontend/build -l 3000" \
  "cd ai && uvicorn app:app --host 0.0.0.0 --port 8000"
