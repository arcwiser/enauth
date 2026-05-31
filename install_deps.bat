@echo off
setlocal
<<<<<<< HEAD
=======
set PY=C:\Users\Weirdo\AppData\Local\Python\pythoncore-3.14-64\python.exe
set PIP=C:\Users\Weirdo\AppData\Local\Python\bin\pip.exe
>>>>>>> 41cd6f0 (auto deploy clean auth system)

echo.
echo  [EnAuth] Installing Python dependencies...
echo.
<<<<<<< HEAD

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
=======
"%PIP%" install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  [!] pip install failed. Trying with python -m pip...
    "%PY%" -m pip install -r requirements.txt
>>>>>>> 41cd6f0 (auto deploy clean auth system)
)

echo.
echo  [*] Dependencies installed.
echo  [*] Run start_server.bat to launch EnAuth.
echo.
pause
