@echo off
setlocal
title Zscaler POV Kit - installer
cd /d "%~dp0"
if not exist "%~dp0pov_kit.py" (
  echo.
  echo   This installer is running from inside the zip, so it can't see the rest of the kit.
  echo.
  echo   1. Close this window.
  echo   2. Right-click the zscaler-pov-kit zip file and choose "Extract All...", then click Extract.
  echo   3. Open the extracted zscaler-pov-kit folder and double-click "Install Zscaler POV Kit.cmd" there.
  echo.
  pause
  exit /b 1
)
echo.
echo   Zscaler POV Kit - installer
echo   ===========================
echo   This will:
echo     - install uv (the free tool the kit runs on) if it isn't installed yet
echo     - copy the kit to %USERPROFILE%\.zscaler-pov-kit\app
echo     - add a "Zscaler POV Console" shortcut to your desktop and Start menu
echo     - let you run "pov-kit" from any terminal
echo   Nothing changes in any Zscaler tenant: the kit only writes what a customer approves.
echo.
pause

if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul && goto haveuv

echo.
echo   Installing uv...
powershell -NoProfile -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul && goto haveuv

where winget >nul 2>nul
if not errorlevel 1 (
  echo   The uv installer didn't work here. Trying winget...
  winget install --id=astral-sh.uv -e --accept-source-agreements --accept-package-agreements
  set "PATH=%LOCALAPPDATA%\Microsoft\WinGet\Links;%PATH%"
)
where uv >nul 2>nul && goto haveuv

echo.
echo   Couldn't install uv. Your laptop's security policy may be blocking the download.
echo   Ask IT to allow astral.sh and github.com downloads, or install uv another way:
echo     https://docs.astral.sh/uv/getting-started/installation/
echo   Then double-click this installer again.
echo.
pause
exit /b 1

:haveuv
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
echo.
echo   Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)...
uv run --quiet --python 3.12 --script "%~dp0pov_kit.py" install
if errorlevel 1 (
  echo.
  echo   Install failed. The message above says why.
  pause
  exit /b 1
)
echo.
echo   Opening the console. Keep this window open while you use it; close it to stop the console.
call "%USERPROFILE%\.zscaler-pov-kit\app\pov-kit.cmd" gui
