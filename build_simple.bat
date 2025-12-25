@echo off
REM =========================================================
REM Simple Build Script for Secure Backup Application
REM Fixed for PowerShell compatibility
REM =========================================================

echo.
echo ========================================
echo    Secure Backup - Build Script v1.1
echo ========================================
echo.

REM =========================================================
REM Step 0: Verify we're in the right directory
REM =========================================================
echo [Step 0/6] Verifying project structure...

if not exist "app" (
    echo ERROR: 'app' folder not found!
    echo Please run this script from the project root directory F:\KLTN
    echo Current directory: %CD%
    pause
    exit /b 1
)

if not exist "gui" (
    echo ERROR: 'gui' folder not found!
    echo Current directory: %CD%
    pause
    exit /b 1
)

if not exist "build" mkdir build

echo OK Project structure verified
echo    - Root: %CD%
echo    - App folder: OK
echo    - GUI folder: OK
echo.

REM =========================================================
REM Step 1: Check Python
REM =========================================================
echo [Step 1/6] Checking Python installation...

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org/
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo OK Python %PYTHON_VERSION% detected
echo.

REM =========================================================
REM Step 2: Check Dependencies
REM =========================================================
echo [Step 2/6] Checking dependencies...

python -c "import cryptography" 2>nul
if errorlevel 1 goto install_deps

python -c "import boto3" 2>nul
if errorlevel 1 goto install_deps

python -c "import customtkinter" 2>nul
if errorlevel 1 goto install_deps

python -c "import watchdog" 2>nul
if errorlevel 1 goto install_deps

python -c "import schedule" 2>nul
if errorlevel 1 goto install_deps

python -c "import PyInstaller" 2>nul
if errorlevel 1 goto install_deps

echo OK All dependencies installed
echo.
goto deps_ok

:install_deps
echo.
echo Installing required packages...
echo This may take a few minutes...
echo.
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install dependencies
    echo Please check your internet connection and try again
    pause
    exit /b 1
)
echo OK Dependencies installed successfully
echo.

:deps_ok

REM =========================================================
REM Step 3: Clean Previous Builds
REM =========================================================
echo [Step 3/6] Cleaning previous builds...

if exist "dist\SecureBackup" (
    echo   Removing dist\SecureBackup...
    rmdir /s /q "dist\SecureBackup" 2>nul
)

if exist "build\SecureBackup" (
    echo   Removing build\SecureBackup...
    rmdir /s /q "build\SecureBackup" 2>nul
)

REM Clean Python cache
for /d /r %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d" 2>nul

echo OK Cleanup completed
echo.

REM =========================================================
REM Step 4: Verify Spec File
REM =========================================================
echo [Step 4/6] Verifying spec file...

if not exist "build\backup_app.spec" (
    echo ERROR: Spec file not found at: build\backup_app.spec
    echo Please make sure the spec file exists
    pause
    exit /b 1
)

echo OK Spec file found
echo.

REM =========================================================
REM Step 5: Build with PyInstaller
REM =========================================================
echo [Step 5/6] Building executable with PyInstaller...
echo This may take 2-5 minutes...
echo.

REM Use absolute path for spec file
set SPEC_PATH=%CD%\build\backup_app.spec

pyinstaller "%SPEC_PATH%" --clean --noconfirm --log-level=WARN

if errorlevel 1 (
    echo.
    echo ========================================
    echo           BUILD FAILED
    echo ========================================
    echo.
    echo Check the error messages above for details.
    echo.
    echo Common issues:
    echo   1. Missing dependencies - Run: pip install -r requirements.txt
    echo   2. Import errors - Check if all modules are in hiddenimports
    echo   3. Path issues - Make sure you're in F:\KLTN directory
    echo.
    pause
    exit /b 1
)

echo.
echo OK Build completed successfully
echo.

REM =========================================================
REM Step 6: Verify Output
REM =========================================================
echo [Step 6/6] Verifying build output...

if not exist "dist\SecureBackup\SecureBackup.exe" (
    echo ERROR: Executable not found!
    echo Expected location: dist\SecureBackup\SecureBackup.exe
    pause
    exit /b 1
)

REM Get file size
for %%F in ("dist\SecureBackup\SecureBackup.exe") do set SIZE=%%~zF
set /a SIZE_MB=%SIZE% / 1048576

echo OK Executable created successfully
echo.
echo ========================================
echo     BUILD COMPLETED SUCCESSFULLY
echo ========================================
echo.
echo Output Information:
echo   Location: %CD%\dist\SecureBackup\
echo   Executable: SecureBackup.exe
echo   Size: ~%SIZE_MB% MB
echo.
echo To run the application:
echo   cd dist\SecureBackup
echo   SecureBackup.exe
echo.
echo ========================================
echo.

pause