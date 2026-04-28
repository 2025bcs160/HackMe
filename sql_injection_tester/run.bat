@echo off
REM SQL Injection Scanner - Windows Batch Runner
REM This script makes it easier to run the SQL Injection Scanner on Windows

echo.
echo ===================================================
echo   SQL Injection Scanner - Windows Runner
echo ===================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org/
    pause
    exit /b 1
)

REM Check if dependencies are installed
python -c "import click" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing required dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Run the main script with all arguments passed through
python main.py %*

pause
