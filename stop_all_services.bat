@echo off
setlocal

set SCRIPT_DIR=%~dp0
set PS_SCRIPT=%SCRIPT_DIR%scripts\stop-all-services.ps1

if not exist "%PS_SCRIPT%" (
  echo [ERROR] Script not found: %PS_SCRIPT%
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
set ERR=%ERRORLEVEL%

if not "%ERR%"=="0" (
  echo [WARN] Stop completed with issues. Some target ports may still be occupied.
) else (
  echo [OK] All target services stopped.
)

pause
exit /b %ERR%
