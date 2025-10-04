# backend/Dockerfile
FROM python:3.12-slim

# (Optional) system packages you might need:
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential libpq-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (cache-friendly)
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app code
COPY backend/ /app/

# Expose port (documentational)
EXPOSE 8000

# Gunicorn command
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
