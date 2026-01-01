FROM python:3.11-slim

# Create non-root user
RUN useradd -m appuser

WORKDIR /app

# Copy application code
COPY app.py /app/
COPY internal_service.py /app/

# Install runtime deps
RUN pip install --no-cache-dir flask PyJWT requests

# Drop privileges: run as non-root
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
