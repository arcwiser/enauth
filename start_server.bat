@echo off
setlocal
cd /d "%~dp0"
set HOST=127.0.0.1
set PORT=8080
set DEBUG=false
set SSL_CERT=
set SSL_KEY=

echo.
echo ======================================
echo   EnAuth Server
echo ======================================
echo.
echo   Admin panel -> https://127.0.0.1:8080/panel/
echo.

python main.py

pause
