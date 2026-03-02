@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%setup-windows.ps1"

if not exist "%PS_SCRIPT%" (
  echo setup-windows.ps1 not found at "%PS_SCRIPT%".
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
exit /b %ERRORLEVEL%
