@echo off
setlocal enabledelayedexpansion

echo ======================================
echo   ENAUTH AUTO GIT DEPLOY TOOL
echo ======================================

REM === YOUR REPO IS HARD-CODED HERE ===
set repo=https://github.com/Steamfrom/enauth.git

echo Using repo:
echo %repo%
echo.

REM === 1. CREATE .GITIGNORE ===
echo [1/5] Creating .gitignore...

(
echo __pycache__/
echo *.pyc
echo .env
echo *.db
echo *.log
echo *.pem
echo venv/
echo node_modules/
) > .gitignore

REM === 2. CLEAN CACHE FILES ===
echo [2/5] Cleaning cache...

for /d /r %%d in (__pycache__) do (
    if exist "%%d" rmdir /s /q "%%d"
)

del /s /q *.pyc 2>nul
del /s /q *.log 2>nul

REM === 3. INIT GIT ===
echo [3/5] Initializing Git...

if not exist ".git" (
    git init
)

REM === 4. COMMIT ===
echo [4/5] Staging + committing...

git add .
git commit -m "auto deploy clean auth system" 2>nul

REM === 5. PUSH ===
echo [5/5] Pushing to GitHub...

git branch -M main

git remote remove origin 2>nul

git remote add origin %repo%

git push -u origin main

echo.
echo ======================================
echo   DONE - DEPLOYED TO GITHUB 🚀
echo ======================================
pause