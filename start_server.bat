@echo off
<<<<<<< HEAD
setlocal EnableExtensions EnableDelayedExpansion
echo [DEBUG] Script path: %~f0
echo [DEBUG] Script dir : %~dp0
echo [DEBUG] CWD before : %CD%
pushd "%~dp0"
if errorlevel 1 (
  echo [ERROR] pushd failed for "%~dp0"
  exit /b 1
)
echo [DEBUG] CWD after  : %CD%
set "HOST=127.0.0.1"
set "PORT=8080"
set "DEBUG=false"
set "SSL_CERT="
set "SSL_KEY="

echo [DEBUG] Looking for listeners on port %PORT%...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$port = %PORT%; " ^
  "$listenerPids = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; " ^
  "if (-not $listenerPids) { Write-Host ('[DEBUG] No listeners found on port ' + $port) } else { " ^
  "  foreach ($listenerPid in $listenerPids) { " ^
  "    Write-Host ('[DEBUG] Stopping process ' + $listenerPid + ' on port ' + $port + '...'); " ^
  "    Stop-Process -Id $listenerPid -Force -ErrorAction SilentlyContinue " ^
  "  } " ^
  "}"

echo [DEBUG] Python launcher:
where py
echo [DEBUG] Python version:
py -3.12 --version
echo [DEBUG] Checking whether port %PORT% is still busy...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$port = %PORT%; " ^
  "$conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue; " ^
  "if ($conns) { " ^
  "  $conns | ForEach-Object { Write-Host ('[DEBUG] Still listening: PID=' + $_.OwningProcess + ' Local=' + $_.LocalAddress + ':' + $_.LocalPort) }; " ^
  "  exit 1 " ^
  "} else { Write-Host ('[DEBUG] Port ' + $port + ' is free') }"

if errorlevel 1 (
  echo [ERROR] Port %PORT% is still busy after cleanup. Stop the process shown above, then rerun.
  popd
  pause
  exit /b 1
)
=======
setlocal
cd /d "%~dp0"
set HOST=127.0.0.1
set PORT=8080
set DEBUG=false
set SSL_CERT=
set SSL_KEY=
>>>>>>> 41cd6f0 (auto deploy clean auth system)

echo.
echo ======================================
echo   EnAuth Server
echo ======================================
echo.
<<<<<<< HEAD
echo   Admin panel -^> http://127.0.0.1:%PORT%/panel/
echo.

echo [DEBUG] Launching server in a new window...
start "EnAuth Server" cmd /k "cd /d ""%~dp0"" && py -3.12 main.py"
echo [DEBUG] Server window launched.

popd
=======
echo   Admin panel -> https://127.0.0.1:8080/panel/
echo.

python main.py

>>>>>>> 41cd6f0 (auto deploy clean auth system)
pause
