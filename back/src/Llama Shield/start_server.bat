@echo off
setlocal EnableExtensions

REM Stable launcher for Llama Shield (ASCII-only to avoid codepage issues)
cd /d "%~dp0"

if not exist ".\venv311\Scripts\python.exe" (
	echo [ERROR] Python interpreter not found: .\venv311\Scripts\python.exe
	exit /b 1
)

echo [INFO] Starting Llama Shield on http://127.0.0.1:18000
call ".\venv311\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 18000

exit /b %errorlevel%
