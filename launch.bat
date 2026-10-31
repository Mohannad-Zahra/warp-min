@echo off
cd /d "%~dp0"
if exist warp-min-new.exe (
    copy /y warp-min-new.exe warp-min.exe >nul 2>&1
    if not errorlevel 1 del /f /q warp-min-new.exe >nul 2>&1
)
warp-min.exe %*
