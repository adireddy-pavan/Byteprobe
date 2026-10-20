@echo off
setlocal
cd /d "%~dp0"
if not exist "verification_results\setup" mkdir "verification_results\setup"
echo Setting up ByteProbe in a local Python virtual environment...
where py >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python launcher 'py' not found. Install Python 3.10+ for Windows, then retry.
  pause
  exit /b 3
)
if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
if errorlevel 1 goto :setupfailed
".venv\Scripts\python.exe" -m pip install -r requirements.txt > "verification_results\setup\dependency_install.txt" 2>&1
if errorlevel 1 goto :setupfailed
".venv\Scripts\python.exe" tools\friend_validation_runner.py basic
set "RESULT=%ERRORLEVEL%"
echo.
echo RESULTS: %CD%\verification_results
echo RESULTS ZIP: %CD%\ByteProbe_Verification_Results.zip
if not "%RESULT%"=="0" echo WARNING: Some tests failed or were incomplete. Send the logs anyway.
pause
exit /b %RESULT%
:setupfailed
echo ERROR during setup. Check verification_results\setup\dependency_install.txt
pause
exit /b 3
