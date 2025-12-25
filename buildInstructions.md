# 🔨 Build Instructions - Secure Backup Application

## 📋 Prerequisites

### Required Software
- **Python 3.9+** (Recommended: Python 3.10 or 3.11)
- **pip** (Python package manager)
- **Git** (Optional, for version control)

### System Requirements
- **OS**: Windows 10/11, Ubuntu 20.04+, or macOS
- **RAM**: Minimum 4GB
- **Disk Space**: 500MB free space for build

## 🚀 Quick Start

### Windows

1. **Clone/Download the project**
```bash
git clone <your-repo-url>
cd KLTN
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Build the application**
```bash
build.bat
```

The executable will be in `dist\SecureBackup\SecureBackup.exe`

### Linux/macOS

1. **Install dependencies**
```bash
pip3 install -r requirements.txt
```

2. **Build with PyInstaller**
```bash
pyinstaller build/backup_app.spec --clean --noconfirm
```

3. **Run the application**
```bash
./dist/SecureBackup/SecureBackup
```

## 📦 Manual Build Steps

### 1. Verify Project Structure
```
KLTN/
├── app/
│   ├── core/
│   ├── crypto/
│   ├── storage/
│   ├── utils/
│   └── watcher/
├── gui/
│   └── backup_app.py
├── build/
│   └── backup_app.spec
├── requirements.txt
└── build.bat
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

**Key Dependencies:**
- `cryptography>=41.0.0` - AES-GCM encryption
- `boto3>=1.28.0` - AWS S3 integration
- `customtkinter>=5.2.0` - Modern GUI
- `watchdog>=3.0.0` - File watching
- `pyinstaller>=6.0.0` - Build tool

### 3. Test Before Building
```bash
# Test if all imports work
python -c "from gui.backup_app import BackupApp; print('OK')"

# Test if modules are accessible
python -c "from app.crypto.encryption import encrypt_file; print('OK')"
```

### 4. Build Executable
```bash
# Clean previous builds
pyinstaller build/backup_app.spec --clean --noconfirm

# Or use the build script
build.bat  # Windows
```

### 5. Test the Executable
```bash
cd dist/SecureBackup
./SecureBackup.exe  # Windows
./SecureBackup      # Linux/macOS
```

## ⚠️ Common Issues & Solutions

### Issue 1: Module Import Errors
**Error:** `ModuleNotFoundError: No module named 'app'`

**Solution:**
```bash
# Make sure you're in the project root
cd KLTN

# Verify PYTHONPATH
set PYTHONPATH=%CD%  # Windows
export PYTHONPATH=$(pwd)  # Linux/macOS

# Rebuild
pyinstaller build/backup_app.spec --clean
```

### Issue 2: Hidden Imports Missing
**Error:** `ImportError` when running the .exe

**Solution:** Add missing modules to `backup_app.spec`:
```python
hiddenimports=[
    'your.missing.module',
    # ... other modules
]
```

### Issue 3: AWS Credentials Not Working
**Error:** `Unable to locate credentials`

**Solution:**
- Configure AWS credentials in the app's Settings tab
- Or set environment variables:
```bash
set AWS_ACCESS_KEY_ID=your_key      # Windows
export AWS_ACCESS_KEY_ID=your_key   # Linux/macOS
```

### Issue 4: Large .exe Size
**Solution:** Exclude unnecessary modules in `.spec`:
```python
excludes=[
    'matplotlib',
    'numpy',
    'pandas',
    # ... other unused modules
]
```

### Issue 5: Build Fails on `customtkinter`
**Solution:**
```bash
# Reinstall customtkinter
pip uninstall customtkinter
pip install customtkinter==5.2.0

# Clear cache and rebuild
pyinstaller build/backup_app.spec --clean --noconfirm
```

## 🔧 Build Configuration

### PyInstaller Options

**In `backup_app.spec`:**

```python
# Console Mode (for debugging)
console=True  # Shows console window with logs

# No Console (production)
console=False  # Hides console window

# One-file vs One-folder
# Current: One-folder (faster startup)
# For one-file: Use --onefile flag
```

### Optimization

**Reduce size:**
```bash
# Use UPX compression (already enabled)
upx=True

# Exclude test files
excludes=['pytest', 'setuptools', 'numpy', 'pandas']
```

**Faster builds:**
```bash
# Don't clean every time
pyinstaller build/backup_app.spec --noconfirm
```

## 📱 Distribution

### Package Structure
```
dist/SecureBackup/
├── SecureBackup.exe       # Main executable
├── _internal/             # Required libraries
│   ├── cryptography/
│   ├── boto3/
│   └── ...
└── config.json (optional) # Pre-configured settings
```

### Create Installer (Optional)
Use **Inno Setup** or **NSIS** to create a proper installer:

```iss
[Setup]
AppName=Secure Backup System
AppVersion=1.0.0
DefaultDirName={pf}\SecureBackup
DefaultGroupName=Secure Backup
OutputDir=installer
OutputBaseFilename=SecureBackup_Setup

[Files]
Source: "dist\SecureBackup\*"; DestDir: "{app}"; Flags: recursesubdirs
```

## 🧪 Testing the Build

### Manual Test Checklist

- [ ] App starts without errors
- [ ] Settings tab: AWS configuration works
- [ ] Settings tab: RSA key generation works
- [ ] Backup tab: Can select folders
- [ ] Backup tab: Encryption works
- [ ] Backup tab: Upload to S3 works
- [ ] Restore tab: Download from S3 works
- [ ] Restore tab: Decryption works
- [ ] Verify tab: Integrity check works
- [ ] Logs display correctly
- [ ] Status indicators update

### Automated Testing (Optional)
```bash
# Unit tests
pytest tests/

# Integration tests
pytest tests/integration/
```

## 📝 Version Management

### Update Version Number

1. In `backup_app.py`:
```python
APP_VERSION = "1.0.1"
```

2. In `backup_app.spec`:
```python
version='1.0.1'
```

3. Rebuild:
```bash
build.bat
```

## 🆘 Getting Help

### Debug Mode
Run with console to see errors:
```bash
# Edit backup_app.spec
console=True

# Rebuild
pyinstaller build/backup_app.spec --clean
```

### Log Files
Check application logs:
```
C:\Users\<username>\.encrypted_backup\logs\  # Windows (built app)
F:\KLTN\logs\                                 # Development mode
```

### Contact
- Email: [your-email]
- GitHub Issues: [your-repo]/issues

## 📚 Additional Resources

- [PyInstaller Documentation](https://pyinstaller.org/en/stable/)
- [CustomTkinter Documentation](https://customtkinter.tomschimansky.com/)
- [Cryptography Documentation](https://cryptography.io/)
- [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

---

**Last Updated:** December 2025  
**Version:** 1.0.0