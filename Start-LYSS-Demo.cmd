@echo off
rem Starts the LYSS demo: six simulated switches of a fictitious company and the web interface
rem on http://127.0.0.1:8766, with its own data folder. Nothing touches your network.
rem The demo administrator password is printed below, once: keep this window open.
cd /d "%~dp0"
call "%~dp0Start-LYSS.cmd" install-only
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" -m lyss demo --open
pause
