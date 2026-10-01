@echo off
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do taskkill /PID %%P /F >nul 2>&1
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":5500" ^| findstr "LISTENING"') do taskkill /PID %%P /F >nul 2>&1
echo SentinelX local services stopped.
pause
