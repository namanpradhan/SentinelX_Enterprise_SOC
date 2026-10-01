@echo off
setlocal
cd /d "%~dp0"
echo SentinelX security-stack availability
for %%T in (nmap suricata snort snort3 msfconsole ollama) do (
  where %%T >nul 2>nul
  if errorlevel 1 (echo [NOT FOUND] %%T) else (echo [FOUND] %%T)
)
echo.
echo Optional tools are intentionally not bundled. Use the official vendors' installers and validate licenses/policies before deployment.
pause
