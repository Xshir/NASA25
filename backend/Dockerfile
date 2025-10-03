FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run with Gunicorn, default 4 workers (can override via env)
CMD ["sh", "-c", "gunicorn -w ${GUNICORN_WORKERS:-4} -b 0.0.0.0:8000 app:app"]
