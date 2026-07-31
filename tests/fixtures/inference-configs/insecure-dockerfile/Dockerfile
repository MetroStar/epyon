FROM python:3.11-slim

WORKDIR /app

# No USER directive — runs as root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Exposes privileged port
EXPOSE 80

CMD ["python", "app.py"]
