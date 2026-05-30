@echo off
setlocal enabledelayedexpansion

echo ======================================
echo   ENAUTH BULLETPROOF GIT DEPLOY
echo ======================================

REM === CONFIG ===
set repo=https://github.com/Steamfrom/enauth.git

REM === SAFETY CHECK: GIT ===
git --version >nul 2>&1
if errorlevel 1 (
    echo Git is not installed. Install Git first.
    pause
    exit /b
)

REM === 1. CREATE .GITIGNORE ===
echo [1/7] Writing .gitignore...

(
echo __pycache__/
echo *.pyc
echo .env
echo *.db
echo *.log
echo *.pem
echo venv/
echo node_modules/
echo server.log*
) > .gitignore

REM === 2. CLEAN CACHE ===
echo [2/7] Cleaning cache files...

for /d /r %%d in (__pycache__) do (
    if exist "%%d" rmdir /s /q "%%d"
)

del /s /q *.pyc 2>nul
del /s /q *.log 2>nul

REM === 3. INIT OR CONFIRM GIT ===
echo [3/7] Checking Git repo...

if not exist ".git" (
    git init
)

REM === 4. SET SAFE USER (avoids warning spam) ===
echo [4/7] Setting Git identity...

git config user.name "auto-deploy"
git config user.email "auto@local.dev"

REM === 5. ADD FILES SAFELY ===
echo [5/7] Staging files...

git add .

REM === 6. COMMIT (ignore empty commit crash) ===
echo [6/7] Committing...

git commit -m "auto deploy clean auth system" >nul 2>&1

REM === 7. HANDLE REMOTE + SYNC ===
echo [7/7] Syncing with GitHub...

git branch -M main

git remote remove origin 2>nul
git remote add origin %repo%

REM === TRY NORMAL PULL FIRST ===
git pull origin main --allow-unrelated-histories --no-edit

REM === PUSH ===
git push origin main

IF ERRORLEVEL 1 (
    echo.
    echo WARNING: Normal push failed. Attempting force push...
    git push -f origin main
)

echo.
echo ======================================
echo   DEPLOY COMPLETE 🚀
echo ======================================
pause