FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    FLASK_DEBUG=False

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$(uname -s)" = "Linux" ]; then pip install uwsgi==2.0.22; fi

# Copy the rest of the application
COPY . .

# Create logs directory
RUN mkdir -p logs && chmod 777 logs

# Run gunicorn (Linux/Mac) or use the run_server.py script (Windows)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--workers=4", "--threads=2", "--timeout=60"] 