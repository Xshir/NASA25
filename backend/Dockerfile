FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy app and static site
COPY app.py .
COPY static ./static

# Gunicorn entrypoint (multi-worker)
CMD ["sh", "-c", "gunicorn -w ${GUNICORN_WORKERS:-4} -b 0.0.0.0:8000 app:app"]
