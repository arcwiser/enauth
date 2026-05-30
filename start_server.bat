@echo off
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
  "$pids = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; " ^
  "if (-not $pids) { Write-Host ('[DEBUG] No listeners found on port ' + $port) } else { " ^
  "  foreach ($pid in $pids) { Write-Host ('[DEBUG] Stopping process ' + $pid + ' on port ' + $port + '...'); Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } " ^
  "}"

echo [DEBUG] Python launcher:
where py
echo [DEBUG] Python version:
py -3.12 --version
echo [DEBUG] Checking whether port %PORT% is still busy...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$port = %PORT%; " ^
  "$conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue; " ^
  "if ($conns) { $conns | ForEach-Object { Write-Host ('[DEBUG] Still listening: PID=' + $_.OwningProcess + ' Local=' + $_.LocalAddress + ':' + $_.LocalPort) } } else { Write-Host ('[DEBUG] Port ' + $port + ' is free') }"

echo.
echo ======================================
echo   EnAuth Server
echo ======================================
echo.
echo   Admin panel -^> http://127.0.0.1:%PORT%/panel/
echo.

echo [DEBUG] Launching server...
py -3.12 main.py
echo [DEBUG] Server exited with code !errorlevel!

popd
pause
