@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%\..\..") do set "REPO_ROOT=%%~fI"

if not exist "%REPO_ROOT%\Cargo.toml" (
  echo Could not locate repo root at "%REPO_ROOT%".
  pause
  exit /b 1
)

net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
  echo Requesting administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%ComSpec%' -ArgumentList '/c','\"\"%~f0\"\"' -Verb RunAs"
  exit /b 0
)

pushd "%REPO_ROOT%"

if not exist "target\debug\piflasher.exe" (
  echo PiFlasher binary not found. Running setup first...
  call "%SCRIPT_DIR%setup-windows.cmd"
  if errorlevel 1 (
    echo Setup failed.
    popd
    pause
    exit /b 1
  )
)

if not exist "rpi.img.xz" (
  echo WARNING: rpi.img.xz was not found in this folder:
  echo   %REPO_ROOT%
  echo Put rpi.img.xz there, then run again.
  popd
  pause
  exit /b 1
)

echo Starting PiFlasher...
echo.
"%REPO_ROOT%\target\debug\piflasher.exe" flash
set "EXIT_CODE=%ERRORLEVEL%"

popd

if not "%EXIT_CODE%"=="0" (
  echo.
  echo PiFlasher exited with code %EXIT_CODE%.
  pause
)

exit /b %EXIT_CODE%
