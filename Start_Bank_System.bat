@echo off
echo ======================================================
echo      STARTING BANK RISK MANAGEMENT SYSTEM
echo ======================================================
echo.
echo Initializing System...
call venv\Scripts\activate

echo.
echo System is running!
echo Access the dashboard at: http://localhost:8080
echo.
echo (Keep this window open while using the software)
echo.

waitress-serve --listen=*:8080 bank_risk_system.wsgi:application

pause