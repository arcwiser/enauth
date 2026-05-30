@echo off
setlocal
set PY=C:\Users\Weirdo\AppData\Local\Python\pythoncore-3.14-64\python.exe
set PIP=C:\Users\Weirdo\AppData\Local\Python\bin\pip.exe

echo.
echo  [EnAuth] Installing Python dependencies...
echo.
"%PIP%" install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  [!] pip install failed. Trying with python -m pip...
    "%PY%" -m pip install -r requirements.txt
)

echo.
echo  [*] Dependencies installed.
echo  [*] Run start_server.bat to launch EnAuth.
echo.
pause
