# Simple learning-focused Dockerfile for SparringPartner
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy only the application code we need
COPY app.py /app/

# Install runtime dependencies (no dev tools, no extras)
RUN pip install --no-cache-dir flask PyJWT

# Environment hints
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Flask listens on port 5000 in app.py
EXPOSE 5000

# Start the Flask app
CMD ["python", "app.py"]
