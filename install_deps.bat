@echo off
setlocal

echo.
echo  [EnAuth] Installing Python dependencies...
echo.

REM Try pip first
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  [!] pip install failed. Trying with python -m pip...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo  [!] python -m pip also failed. Trying with py launcher...
        py -m pip install -r requirements.txt
    )
)

echo.
echo  [*] Dependencies installed.
echo  [*] Run start_server.bat to launch EnAuth.
echo.
pause
