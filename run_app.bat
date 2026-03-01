@echo off
echo ==================================
echo     Starting PhishGuard System
echo ==================================

echo Killing old Python processes...
taskkill /IM python.exe /F > nul 2>&1

echo Starting Backend...
start cmd /k "python -m uvicorn backend.main:app --reload"

timeout /t 3 > nul

echo Starting Frontend...
start cmd /k "cd frontend && python -m http.server 8080"

echo ==================================
echo System Started Successfully!
echo Open http://localhost:8080
echo ==================================
pause