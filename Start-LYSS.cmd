@echo off
rem Starts the LYSS web interface (local only) and opens it in the default browser.
rem First start: creates .venv and installs LYSS (needs Python 3.10 or later and internet access).
rem If LYSS is already running on port 8765, it only opens the browser.
cd /d "%~dp0"
call :install
if errorlevel 1 exit /b 1
if /i "%~1"=="install-only" exit /b 0
netstat -ano -p tcp | findstr /r /c:"127\.0\.0\.1:8765 .*LISTENING" >nul
if %errorlevel%==0 (
  echo LYSS is already running. Close its window first to restart it with new code.
  start "" http://127.0.0.1:8765
  timeout /t 4 >nul
  exit /b 0
)
start "" http://127.0.0.1:8765
".venv\Scripts\python.exe" -m lyss ui --port 8765
exit /b 0

:install
if exist ".venv\Scripts\python.exe" exit /b 0
echo First start: installing LYSS into the .venv folder. This takes a minute or two.
where py >nul 2>nul
if %errorlevel%==0 (py -3 -m venv .venv) else (python -m venv .venv)
if not exist ".venv\Scripts\python.exe" (
  echo Python 3.10 or later is required: https://www.python.org/downloads/
  echo During its installation, tick "Add python.exe to PATH", then start this file again.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -e .
if errorlevel 1 (
  echo Installation failed: see the messages above. Delete the .venv folder before trying again.
  pause
  exit /b 1
)
echo LYSS is installed.
exit /b 0
