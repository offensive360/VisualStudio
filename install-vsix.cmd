@echo off
REM ============================================================================
REM Offensive 360 - Visual Studio Extension Installer
REM ============================================================================
REM
REM IMPORTANT: Run this script from a regular Command Prompt (cmd.exe) or by
REM double-clicking. Do NOT run it from Git Bash / MSYS / WSL / Cygwin --
REM those shells convert leading-slash arguments (like "/admin") into Windows
REM paths under their install root (e.g., "C:\Program Files\Git\admin"),
REM which causes VSIXInstaller to fail with "Path to vsix file is invalid".
REM
REM Usage:
REM   install-vsix.cmd                          (installs the .vsix in this folder)
REM   install-vsix.cmd "C:\path\to\plugin.vsix" (installs the specified file)
REM ============================================================================

setlocal enabledelayedexpansion

set "VSIX=%~1"
if "%VSIX%"=="" (
    for %%f in ("%~dp0*.vsix") do set "VSIX=%%~ff"
)
if "%VSIX%"=="" (
    echo [ERROR] No .vsix file specified and none found in script folder.
    echo Usage: install-vsix.cmd "C:\path\to\plugin.vsix"
    exit /b 1
)
if not exist "%VSIX%" (
    echo [ERROR] File not found: %VSIX%
    exit /b 1
)

echo Locating VSIXInstaller.exe...
set "VSIXINSTALLER="
for %%R in ("%ProgramFiles%" "%ProgramFiles(x86)%") do (
    for /d %%Y in ("%%~R\Microsoft Visual Studio\*") do (
        for /d %%E in ("%%~Y\*") do (
            if exist "%%~E\Common7\IDE\VSIXInstaller.exe" (
                set "VSIXINSTALLER=%%~E\Common7\IDE\VSIXInstaller.exe"
            )
        )
    )
)

if "%VSIXINSTALLER%"=="" (
    echo [ERROR] VSIXInstaller.exe not found. Install Visual Studio first.
    exit /b 1
)

echo Found: %VSIXINSTALLER%
echo Installing: %VSIX%
echo.
echo NOTE: Visual Studio must be CLOSED before installing.
echo.

REM Use the absolute path with quotes; do NOT pass /admin from this script.
REM /admin is only needed for per-machine installs, and triggers the MSYS
REM path-conversion bug if the script is run from Git Bash.
"%VSIXINSTALLER%" /quiet "%VSIX%"
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" (
    echo.
    echo [OK] Installation complete. Start Visual Studio to use the extension.
) else (
    echo.
    echo [ERROR] VSIXInstaller exit code: %RC%
    echo Check %TEMP% for VSIX install logs.
)

exit /b %RC%
