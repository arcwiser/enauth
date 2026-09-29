@echo off
setlocal
cd /d "%~dp0"

if not exist ".env" (
    echo [!] Missing .env file. Copy .env.example to .env and configure it first.
    exit /b 1
)

echo.
echo ======================================
echo   EnAuth Server
echo ======================================
echo   Admin panel: http://127.0.0.1:8080/panel/
echo.

where py >nul 2>nul
if not errorlevel 1 (
    py -3.12 main.py
    if not errorlevel 9009 exit /b %errorlevel%
)

where python >nul 2>nul
if errorlevel 1 (
    echo [!] Python was not found. Install Python 3.12 or later.
    exit /b 1
)
python main.py
