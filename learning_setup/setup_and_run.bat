@echo off
REM Cybersecurity Learning Setup Script
REM This script sets up a safe learning environment for SQL injection testing

echo.
echo ===================================================
echo   Cybersecurity Learning Environment Setup
echo ===================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo Please install Python 3.7+ from https://www.python.org/
    echo.
    pause
    exit /b 1
)

echo [*] Python found. Installing dependencies...

REM Install Flask for the vulnerable app
pip install flask

if errorlevel 1 (
    echo [ERROR] Failed to install Flask
    pause
    exit /b 1
)

echo [*] Dependencies installed successfully!

REM Change to the learning setup directory
cd /d "%~dp0"

echo.
echo ===================================================
echo   Starting Vulnerable Learning Application
echo ===================================================
echo.
echo [IMPORTANT SECURITY NOTICE]
echo This application is INTENTIONALLY VULNERABLE!
echo It should ONLY be used for learning cybersecurity.
echo.
echo - The app will run on http://localhost:5000
echo - Use your SQL injection scanner to test it
echo - NEVER run this on a public server!
echo - Stop the server with Ctrl+C when done
echo.
echo ===================================================
echo.

REM Start the vulnerable Flask app
python vulnerable_app.py

pause