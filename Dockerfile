FROM node:18

RUN apt-get update && apt-get install -y python3 python3-pip python3-venv

WORKDIR /app

COPY backend/package*.json ./backend/
RUN cd backend && npm install

COPY frontend/package*.json ./frontend/
RUN cd frontend && npm install

COPY ai/requirements.txt ./ai/
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r ai/requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN cd frontend && npm run build

RUN npm install -g concurrently serve

EXPOSE 4000 3000 8000

CMD concurrently \
  "cd backend && npm start" \
  "cd frontend && serve -s build -l 3000" \
  "cd ai && uvicorn app:app --host 0.0.0.0 --port 8000"
