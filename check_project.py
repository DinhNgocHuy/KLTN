#!/usr/bin/env python3
"""
Project Health Check Script
Kiểm tra cấu trúc dự án và dependencies trước khi build
"""

import sys
import os
from pathlib import Path
import importlib.util

# Colors for terminal
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{text:^60}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.RESET}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_info(text):
    print(f"  {text}")

def check_python_version():
    """Kiểm tra phiên bản Python"""
    print_header("1. Python Version Check")
    
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    
    print_info(f"Python version: {version_str}")
    
    if version.major == 3 and version.minor >= 9:
        print_success(f"Python {version_str} is compatible")
        return True
    else:
        print_error(f"Python {version_str} is too old. Need 3.9+")
        return False

def check_project_structure():
    """Kiểm tra cấu trúc thư mục dự án"""
    print_header("2. Project Structure Check")
    
    project_root = Path.cwd()
    print_info(f"Project root: {project_root}")
    
    required_dirs = [
        'app',
        'app/core',
        'app/crypto',
        'app/storage',
        'app/utils',
        'gui',
        'build',
    ]
    
    required_files = [
        'gui/backup_app.py',
        'build/backup_app.spec',
        'requirements.txt',
    ]
    
    all_ok = True
    
    # Check directories
    print("\nRequired directories:")
    for dir_path in required_dirs:
        full_path = project_root / dir_path
        if full_path.exists() and full_path.is_dir():
            print_success(f"{dir_path}/")
        else:
            print_error(f"{dir_path}/ - NOT FOUND")
            all_ok = False
    
    # Check files
    print("\nRequired files:")
    for file_path in required_files:
        full_path = project_root / file_path
        if full_path.exists() and full_path.is_file():
            size = full_path.stat().st_size
            if size > 0:
                print_success(f"{file_path} ({size} bytes)")
            else:
                print_warning(f"{file_path} (EMPTY FILE)")
        else:
            print_error(f"{file_path} - NOT FOUND")
            all_ok = False
    
    return all_ok

def check_module_imports():
    """Kiểm tra các module quan trọng có import được không"""
    print_header("3. Module Import Check")
    
    modules_to_check = [
        ('app.core.settings', 'Core Settings'),
        ('app.core.config_manager', 'Config Manager'),
        ('app.core.logging_config', 'Logging Config'),
        ('app.crypto.encryption', 'Encryption'),
        ('app.crypto.decryption', 'Decryption'),
        ('app.crypto.rsa_utils', 'RSA Utils'),
        ('app.storage.s3_upload', 'S3 Upload'),
        ('app.storage.s3_download', 'S3 Download'),
    ]
    
    all_ok = True
    
    for module_name, display_name in modules_to_check:
        try:
            spec = importlib.util.find_spec(module_name)
            if spec is not None:
                print_success(f"{display_name} ({module_name})")
            else:
                print_error(f"{display_name} ({module_name}) - Not found")
                all_ok = False
        except Exception as e:
            print_error(f"{display_name} ({module_name}) - Error: {e}")
            all_ok = False
    
    return all_ok

def check_dependencies():
    """Kiểm tra các thư viện bên ngoài"""
    print_header("4. Dependencies Check")
    
    dependencies = [
        ('cryptography', 'Cryptography Library'),
        ('boto3', 'AWS SDK'),
        ('customtkinter', 'CustomTkinter GUI'),
        ('watchdog', 'File Watcher'),
        ('schedule', 'Scheduler'),
        ('PIL', 'Pillow/PIL'),
    ]
    
    all_ok = True
    
    for module_name, display_name in dependencies:
        try:
            module = __import__(module_name)
            version = getattr(module, '__version__', 'unknown')
            print_success(f"{display_name}: {version}")
        except ImportError:
            print_error(f"{display_name} - NOT INSTALLED")
            all_ok = False
    
    return all_ok

def check_pyinstaller():
    """Kiểm tra PyInstaller"""
    print_header("5. PyInstaller Check")
    
    try:
        import PyInstaller
        version = PyInstaller.__version__
        print_success(f"PyInstaller {version} installed")
        return True
    except ImportError:
        print_error("PyInstaller not installed")
        print_info("Install with: pip install pyinstaller")
        return False

def check_spec_file():
    """Kiểm tra spec file"""
    print_header("6. Spec File Analysis")
    
    spec_file = Path('build/backup_app.spec')
    
    if not spec_file.exists():
        print_error("Spec file not found at build/backup_app.spec")
        return False
    
    print_success(f"Spec file found: {spec_file}")
    
    # Read and analyze spec file
    content = spec_file.read_text(encoding='utf-8')
    
    checks = [
        ("Analysis(", "Analysis configuration"),
        ("hiddenimports", "Hidden imports list"),
        ("app.crypto", "Crypto module imports"),
        ("app.storage", "Storage module imports"),
        ("customtkinter", "CustomTkinter import"),
        ("EXE(", "Executable configuration"),
    ]
    
    print("\nSpec file content analysis:")
    all_found = True
    for check_str, description in checks:
        if check_str in content:
            print_success(description)
        else:
            print_warning(f"{description} - Not found")
            all_found = False
    
    return all_found

def generate_summary(results):
    """Tạo tóm tắt kết quả"""
    print_header("SUMMARY")
    
    total = len(results)
    passed = sum(results.values())
    
    print(f"Total checks: {total}")
    print(f"Passed: {Colors.GREEN}{passed}{Colors.RESET}")
    print(f"Failed: {Colors.RED}{total - passed}{Colors.RESET}")
    
    print("\nDetailed Results:")
    for check_name, result in results.items():
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {check_name}: {status}")
    
    if all(results.values()):
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ All checks passed! Ready to build.{Colors.RESET}")
        print(f"\nNext steps:")
        print(f"  1. Run: build_simple.bat")
        print(f"  2. Or: pyinstaller build/backup_app.spec --clean --noconfirm")
        return True
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}✗ Some checks failed. Please fix the issues above.{Colors.RESET}")
        return False

def main():
    """Main entry point"""
    print(f"{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     Secure Backup - Project Health Check v1.0           ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    # Run all checks
    results = {
        "Python Version": check_python_version(),
        "Project Structure": check_project_structure(),
        "Module Imports": check_module_imports(),
        "Dependencies": check_dependencies(),
        "PyInstaller": check_pyinstaller(),
        "Spec File": check_spec_file(),
    }
    
    # Generate summary
    all_passed = generate_summary(results)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Check interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)