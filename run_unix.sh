#!/bin/bash
echo "Starting Finance Manager..."

# Create logs directory if it doesn't exist
mkdir -p logs

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python is not found. Please make sure Python is installed correctly."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=production
export FLASK_DEBUG=False

# Run the application with gunicorn
echo "Starting server..."
gunicorn --bind 0.0.0.0:5000 app:app --workers=4 --threads=2 --timeout=60 