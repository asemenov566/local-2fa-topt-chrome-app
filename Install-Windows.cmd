@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0native\Install.ps1"
if errorlevel 1 exit /b 1
echo Reload Local 2FA Authenticator at chrome://extensions
pause
