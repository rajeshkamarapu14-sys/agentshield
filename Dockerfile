# AgentShield — container image for the deployable firewall API.
# Runs the deterministic firewall by default; Gemini stays optional via env vars.
FROM python:3.13-slim

# Don't buffer stdout/stderr (better container logs); no .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY . .

# Cloud Run provides $PORT; default to 8080 locally.
ENV PORT=8080
EXPOSE 8080

# Start the FastAPI service. Uses the shell form so $PORT is expanded.
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
