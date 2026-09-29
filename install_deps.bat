@echo off
setlocal
cd /d "%~dp0"

echo.
echo  [EnAuth] Installing Python dependencies...
echo.

where py >nul 2>nul
if not errorlevel 1 (
    py -3.12 -m pip install -r requirements.txt
    if not errorlevel 1 goto done
    py -m pip install -r requirements.txt
    if not errorlevel 1 goto done
)

where python >nul 2>nul
if errorlevel 1 goto missing
python -m pip install -r requirements.txt
if errorlevel 1 goto failed

:done
echo.
echo  [*] Dependencies installed.
echo  [*] Run start_server.bat to launch EnAuth.
exit /b 0

:missing
echo  [!] Python was not found. Install Python 3.12 or later and try again.
exit /b 1

:failed
echo  [!] Dependency installation failed.
exit /b 1
