@echo off
echo Starting PhishGuard Watcher...
echo Press Ctrl+C to stop.
echo.
python -m pytest_watch tests/
