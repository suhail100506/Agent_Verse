@echo off
echo ===================================================
echo     Starting CyberVerse Multi-Agent Platform
echo ===================================================

:: Start Backend
echo [1/2] Starting Backend Server...
start "CyberVerse Backend" cmd /k "cd backend && uv run uvicorn src.fake_certificate_verification_agent.main:app --reload --port 8000"

:: Start Frontend
echo [2/2] Starting Frontend Server...
start "CyberVerse Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo All services are starting! 
echo Backend will be available at: http://localhost:8000
echo Frontend will be available at: http://localhost:5173
echo.
echo You can close this window now. The servers are running in separate windows.
pause
