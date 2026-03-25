@echo off
setlocal

set SCRIPT_DIR=%~dp0
set PS_SCRIPT=%SCRIPT_DIR%scripts\restart-all-services.ps1

if not exist "%PS_SCRIPT%" (
  echo [ERROR] Script not found: %PS_SCRIPT%
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
set ERR=%ERRORLEVEL%

if not "%ERR%"=="0" (
  echo [WARN] Restart completed with issues. Please check opened service terminals.
) else (
  echo [OK] All services restarted successfully.
)

pause
exit /b %ERR%
