@echo off
echo ======================================================
echo      BANK RISK SYSTEM - INSTALLATION WIZARD
echo ======================================================
echo.
echo [1/3] Creating secure virtual environment...
python -m venv venv

echo.
echo [2/3] Activating environment...
call venv\Scripts\activate

echo.
echo [3/3] Installing required banking libraries...
pip install -r requirements.txt

echo.
echo ======================================================
echo      INSTALLATION COMPLETE!
echo ======================================================
echo.
echo You can now delete this file and use "Start_Bank_System.bat"
pause