# Dockerfile (at repo root)
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app code
COPY backend/ /app/
COPY static/ /app/static/

EXPOSE 8000
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8000", "app:app"]
