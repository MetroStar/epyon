FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Copy with proper ownership
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

# Use non-root user
USER appuser

# Expose non-privileged port
EXPOSE 8080

CMD ["python", "app.py"]
