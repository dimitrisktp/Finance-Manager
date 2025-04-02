@echo off
echo Starting Finance Manager...

REM Create logs directory if it doesn't exist
if not exist logs mkdir logs

REM Check if Python is in PATH
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Python is not found in your PATH. Please make sure Python is installed correctly.
    goto :end
)

REM Check if virtual environment exists
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Set environment variables
set FLASK_APP=app.py
set FLASK_ENV=production
set FLASK_DEBUG=False

REM Run the application
echo Starting server...
python run_server.py

:end
pause 