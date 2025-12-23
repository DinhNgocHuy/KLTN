@echo off
echo ====================================
echo Building Secure Backup Application
echo ====================================

set VENV=.venv

if not exist %VENV% (
    python -m venv %VENV%
)

call %VENV%\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

pyinstaller backup_app.spec --clean --noconfirm

echo.
echo Build completed!
echo Output: dist\backup_app.exe
pause
