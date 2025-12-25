import os
import sys
import threading
import queue
import logging
import time
import json
from pathlib import Path
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk

# =========================================================
# CRITICAL: Import settings FIRST to initialize paths
# =========================================================
from app.core.settings import set_bucket_name, DATA_DIR, KEY_DIR, get_bucket_name
from app.crypto.encryption import encrypt_file
from app.crypto.decryption import decrypt_file  
from app.crypto.key_management import rotate_keys_programmatic
from app.crypto.rsa_utils import (
    generate_rsa_keys,
    get_current_rsa_version,
    set_current_rsa_version,
)
from app.storage.s3_upload import upload_file_to_s3
from app.storage.s3_download import download_file_pair
from app.storage.verify_integrity import verify_all_files, verify_local
from app.core.config_manager import load_config, save_config
from app.utils.checksum import sha256_file

# =========================================================
# CONSTANTS
# =========================================================
DEFAULT_REGION = "ap-southeast-1"
LOG_DIR = Path(DATA_DIR).parent / "logs"
LOG_DIR.mkdir(exist_ok=True, parents=True)

ORIGINAL_DIR = Path(DATA_DIR) / "original"
ENCRYPTED_DIR = Path(DATA_DIR)
DECRYPTED_DIR = Path(DATA_DIR) / "decrypted"
DOWNLOADED_DIR = Path(DATA_DIR) / "downloaded"

for d in [ORIGINAL_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, DOWNLOADED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# =========================================================
# LOGGING SETUP
# =========================================================
log_queue = queue.Queue()

class UILogHandler(logging.Handler):
    def emit(self, record):
        try:
            log_queue.put(self.format(record))
        except:
            pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
        UILogHandler(),
    ],
)

logger = logging.getLogger(__name__)

# =========================================================
# MAIN APP CLASS
# =========================================================
class BackupApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Secure Backup System – AES-GCM + RSA + S3")
        self.geometry("1200x800")
        
        # App state
        self.s3_ready = False
        self.rsa_ready = False
        self.selected_folder = None
        self.rsa_password = None
        self.s3_file_list = []  # Cache for S3 file list
        
        # Load existing config
        self._load_existing_config()
        
        # Build UI
        self._build_layout()
        
        # Start log polling
        self.after(200, self._poll_log)
        
        # Check initial state
        self._check_initial_state()

    def _load_existing_config(self):
        """Load existing configuration on startup"""
        try:
            config = load_config()
            
            # Check if AWS is configured
            aws_config = config.get("aws", {})
            if aws_config.get("access_key") and aws_config.get("bucket_name"):
                # Set environment variables
                os.environ["AWS_ACCESS_KEY_ID"] = aws_config["access_key"]
                os.environ["AWS_SECRET_ACCESS_KEY"] = aws_config.get("secret_key", "")
                os.environ["AWS_DEFAULT_REGION"] = aws_config.get("region", DEFAULT_REGION)
                os.environ["AWS_S3_BUCKET"] = aws_config["bucket_name"]
                
                # Set bucket name in settings module
                set_bucket_name(aws_config["bucket_name"])
                
                self.s3_ready = True
                logger.info(f"AWS config loaded: bucket={aws_config['bucket_name']}")
                
        except Exception as e:
            logger.warning(f"Could not load config: {e}")

    def _check_initial_state(self):
        """Check if RSA keys exist"""
        try:
            version = get_current_rsa_version()
            self.rsa_ready = True
            logger.info(f"RSA keys found: {version}")
        except:
            self.rsa_ready = False
            logger.warning("No RSA keys found. Please generate keys first.")

    # =====================================================
    # LAYOUT
    # =====================================================
    def _build_layout(self):
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)

        # Main content area
        self.content = ctk.CTkFrame(self)
        self.content.pack(side="right", expand=True, fill="both", padx=10, pady=10)

        # Sidebar title
        ctk.CTkLabel(
            self.sidebar,
            text="Secure Backup",
            font=("Arial", 20, "bold"),
        ).pack(pady=20)

        # Navigation buttons
        nav_buttons = [
            ("⚙️ Settings", self.show_settings),
            ("📦 Backup", self.show_backup),
            ("🔄 Restore", self.show_restore),
            ("✅ Verify", self.show_verify),
        ]

        for text, command in nav_buttons:
            ctk.CTkButton(
                self.sidebar,
                text=text,
                command=command,
                height=40
            ).pack(pady=8, padx=15, fill="x")

        # Status indicators
        self.status_frame = ctk.CTkFrame(self.sidebar)
        self.status_frame.pack(side="bottom", pady=20, padx=15, fill="x")
        
        ctk.CTkLabel(self.status_frame, text="Status:", font=("Arial", 12, "bold")).pack()
        
        self.s3_status = ctk.CTkLabel(self.status_frame, text="☁️ S3: Not Ready", text_color="orange")
        self.s3_status.pack(pady=2)
        
        self.rsa_status = ctk.CTkLabel(self.status_frame, text="🔑 RSA: Not Ready", text_color="orange")
        self.rsa_status.pack(pady=2)

        # Log box at bottom
        log_label = ctk.CTkLabel(self.content, text="📋 Activity Log", font=("Arial", 14, "bold"))
        log_label.pack(side="bottom", anchor="w", padx=10)
        
        self.log_box = ctk.CTkTextbox(self.content, height=180)
        self.log_box.pack(side="bottom", fill="x", padx=10, pady=5)

        # Show settings by default
        self.show_settings()
        self._update_status()

    def _update_status(self):
        """Update status indicators"""
        if self.s3_ready:
            self.s3_status.configure(text="☁️ S3: Ready", text_color="green")
        else:
            self.s3_status.configure(text="☁️ S3: Not Ready", text_color="orange")
            
        if self.rsa_ready:
            self.rsa_status.configure(text="🔑 RSA: Ready", text_color="green")
        else:
            self.rsa_status.configure(text="🔑 RSA: Not Ready", text_color="orange")

    def _clear_content(self):
        """Clear content area except log box"""
        for widget in self.content.winfo_children():
            if widget is not self.log_box and widget is not self.log_box.master:
                widget.destroy()

    # =====================================================
    # SETTINGS TAB
    # =====================================================
    def show_settings(self):
        self._clear_content()

        # Main frame
        main_frame = ctk.CTkScrollableFrame(self.content)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="⚙️ Settings & Configuration",
            font=("Arial", 24, "bold"),
        ).pack(pady=(0, 30))

        # AWS Configuration
        aws_frame = ctk.CTkFrame(main_frame)
        aws_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(aws_frame, text="AWS Configuration", font=("Arial", 16, "bold")).pack(pady=10)

        # Pre-fill existing config
        config = load_config()
        aws_config = config.get("aws", {})

        self.aws_key = ctk.CTkEntry(aws_frame, placeholder_text="AWS Access Key ID", width=400)
        self.aws_key.pack(pady=5, padx=20)
        if aws_config.get("access_key"):
            self.aws_key.insert(0, aws_config["access_key"])

        self.aws_secret = ctk.CTkEntry(
            aws_frame,
            placeholder_text="AWS Secret Access Key",
            show="*",
            width=400
        )
        self.aws_secret.pack(pady=5, padx=20)
        if aws_config.get("secret_key"):
            self.aws_secret.insert(0, aws_config["secret_key"])

        self.bucket_entry = ctk.CTkEntry(
            aws_frame,
            placeholder_text="S3 Bucket Name",
            width=400
        )
        self.bucket_entry.pack(pady=5, padx=20)
        if aws_config.get("bucket_name"):
            self.bucket_entry.insert(0, aws_config["bucket_name"])

        ctk.CTkButton(
            aws_frame,
            text="💾 Save & Test AWS Connection",
            command=self.save_and_test_aws,
            height=40
        ).pack(pady=15)

        # RSA Configuration
        rsa_frame = ctk.CTkFrame(main_frame)
        rsa_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(rsa_frame, text="RSA Key Configuration", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Show current version
        try:
            current_version = get_current_rsa_version()
            version_text = f"Current Version: {current_version}"
            version_color = "green"
        except:
            version_text = "No RSA keys found"
            version_color = "orange"
        
        ctk.CTkLabel(
            rsa_frame,
            text=version_text,
            font=("Arial", 13, "bold"),
            text_color=version_color
        ).pack(pady=5)
        
        ctk.CTkLabel(
            rsa_frame,
            text=f"Key Directory: {KEY_DIR / 'rsa'}",
            font=("Arial", 11)
        ).pack(pady=5)

        btn_frame = ctk.CTkFrame(rsa_frame)
        btn_frame.pack(pady=10)

        ctk.CTkButton(
            btn_frame,
            text="🔑 Generate Initial RSA Keys",
            command=self.init_rsa,
            width=200
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="🔄 Rotate RSA Keys",
            command=self.rotate_rsa,
            width=200
        ).pack(side="left", padx=5)

        if self.rsa_ready and not self.rsa_password:
        # Prompt once on first access
            dialog = ctk.CTkInputDialog(
                text="Enter RSA password (will be cached for this session):",
                title="RSA Password"
            )
            self.rsa_password = dialog.get_input()

    def save_and_test_aws(self):
        """Save AWS config and test connection"""
        try:
            access_key = self.aws_key.get().strip()
            secret_key = self.aws_secret.get().strip()
            bucket = self.bucket_entry.get().strip()

            if not access_key or not secret_key or not bucket:
                messagebox.showerror("Error", "Please fill all AWS fields")
                return

            # Set environment variables
            os.environ["AWS_ACCESS_KEY_ID"] = access_key
            os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
            os.environ["AWS_DEFAULT_REGION"] = DEFAULT_REGION

            # Test connection
            s3 = boto3.client("s3", region_name=DEFAULT_REGION)

            try:
                s3.head_bucket(Bucket=bucket)
                logger.info(f"✓ S3 bucket exists: {bucket}")
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == '404':
                    # Bucket doesn't exist, create it
                    s3.create_bucket(
                        Bucket=bucket,
                        CreateBucketConfiguration={'LocationConstraint': DEFAULT_REGION}
                    )
                    logger.info(f"✓ S3 bucket created: {bucket}")
                else:
                    raise

            # Save to config file
            config = load_config()
            config["aws"] = {
                "access_key": access_key,
                "secret_key": secret_key,
                "bucket_name": bucket,
                "region": DEFAULT_REGION
            }
            save_config(config)

            # Update runtime state
            os.environ["AWS_S3_BUCKET"] = bucket
            set_bucket_name(bucket)
            self.s3_ready = True
            self._update_status()

            messagebox.showinfo("Success", "AWS configuration saved and tested successfully!")
            logger.info("✓ AWS configuration saved")

        except Exception as e:
            self.s3_ready = False
            self._update_status()
            logger.error(f"AWS configuration failed: {e}")
            messagebox.showerror("Error", f"AWS configuration failed:\n{str(e)}")

    def init_rsa(self):
        """Generate initial RSA key pair"""
        try:
            # Check if already exists
            try:
                version = get_current_rsa_version()
                if messagebox.askyesno("Keys Exist", 
                    f"RSA keys already exist (version: {version}).\nDo you want to continue and create new keys?"):
                    pass
                else:
                    return
            except:
                pass

            # Get password
            dialog = ctk.CTkInputDialog(
                text="Enter password for RSA keys (min 6 characters):",
                title="RSA Key Generation"
            )
            password = dialog.get_input()

            if not password or len(password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return

            # Confirm password
            dialog2 = ctk.CTkInputDialog(
                text="Confirm password:",
                title="Confirm Password"
            )
            password2 = dialog2.get_input()

            if password != password2:
                messagebox.showerror("Error", "Passwords do not match")
                return

            # Generate keys
            logger.info("Generating RSA key pair v1...")
            generate_rsa_keys(password, "v1")
            set_current_rsa_version("v1")
            
            self.rsa_ready = True
            self.rsa_password = password
            self._update_status()

            logger.info("✓ RSA keys generated successfully")
            messagebox.showinfo("Success", "RSA keys generated successfully!\nVersion: v1")

        except Exception as e:
            logger.error(f"RSA generation failed: {e}")
            messagebox.showerror("Error", f"Failed to generate RSA keys:\n{str(e)}")

    def rotate_rsa(self):
        """Rotate RSA keys - KHÔNG CẦN NHẬP MẬT KHẨU MỚI"""
        try:
        # Chỉ cần password hiện tại
            dialog = ctk.CTkInputDialog(
                text="Enter current RSA password:",
                title="RSA Key Rotation"
            )
            password = dialog.get_input()

            if not password:
                return

        # Rotate với CÙNG password
            success = rotate_keys_programmatic(password, delete_old_key=False)
        
            if success:
                messagebox.showinfo("Success", "RSA keys rotated successfully!")
            else:
                messagebox.showerror("Error", "Key rotation failed. Check logs.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to rotate keys: {e}")
            logger.error(f"Key rotation error: {e}", exc_info=True)

    # =====================================================
    # BACKUP TAB
    # =====================================================
    def show_backup(self):
        self._clear_content()

        main_frame = ctk.CTkScrollableFrame(self.content)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="📦 Backup - Encrypt & Upload",
            font=("Arial", 24, "bold"),
        ).pack(pady=(0, 20))

        # Check readiness
        if not self.s3_ready or not self.rsa_ready:
            warning = ctk.CTkLabel(
                main_frame,
                text="⚠️ Please configure AWS and RSA keys in Settings first",
                font=("Arial", 14),
                text_color="orange"
            )
            warning.pack(pady=20)
            return

        # Folder selection
        select_frame = ctk.CTkFrame(main_frame)
        select_frame.pack(fill="x", pady=10)

        ctk.CTkButton(
            select_frame,
            text="📁 Select Folder to Backup",
            command=self.choose_backup_folder,
            height=40
        ).pack(pady=10)

        self.folder_label = ctk.CTkLabel(
            select_frame,
            text="No folder selected",
            font=("Arial", 12)
        )
        self.folder_label.pack(pady=5)

        # Progress
        self.backup_progress = ctk.CTkProgressBar(main_frame)
        self.backup_progress.pack(fill="x", pady=10)
        self.backup_progress.set(0)

        # Timing labels
        self.encrypt_time_label = ctk.CTkLabel(main_frame, text="Encryption time: --", font=("Arial", 11))
        self.encrypt_time_label.pack(pady=2)
        
        self.upload_time_label = ctk.CTkLabel(main_frame, text="Upload time: --", font=("Arial", 11))
        self.upload_time_label.pack(pady=2)

        # Backup button
        self.btn_backup = ctk.CTkButton(
            main_frame,
            text="🚀 Start Backup (Encrypt & Upload)",
            command=self.run_backup,
            height=50,
            font=("Arial", 14, "bold"),
            state="disabled"
        )
        self.btn_backup.pack(pady=20)

    def choose_backup_folder(self):
        """Choose folder for backup"""
        path = filedialog.askdirectory(title="Select folder to backup")
        if path:
            self.selected_folder = Path(path)
            self.folder_label.configure(text=f"Selected: {self.selected_folder}")
            self.btn_backup.configure(state="normal")
            logger.info(f"Selected folder for backup: {self.selected_folder}")

    def run_backup(self):
        """Execute backup process with detailed timing"""
        if not self.selected_folder:
            messagebox.showwarning("Warning", "Please select a folder first")
            return

        # Get RSA password if not cached
        if not self.rsa_password:
            dialog = ctk.CTkInputDialog(
                text="Enter RSA password:",
                title="RSA Password Required"
            )
            self.rsa_password = dialog.get_input()
            
            if not self.rsa_password:
                return

        def worker():
            try:
                self.backup_progress.set(0.1)
                logger.info("=== BACKUP STARTED ===")
                logger.info(f"Source: {self.selected_folder}")
                logger.info(f"Destination: {ENCRYPTED_DIR}")

                # ===== ENCRYPTION PHASE =====
                encrypt_start = time.time()
                logger.info("Encrypting files...")
                
                import glob
                files = [
                    f for f in glob.glob(str(self.selected_folder / "**" / "*"), recursive=True)
                    if os.path.isfile(f)
                ]
                
                logger.info(f"Found {len(files)} files to encrypt")
                
                # ✅ FIX: Chỉ pass base directory
                for idx, file_path in enumerate(files):
                    file_name = Path(file_path).name
                    
                    logger.info(f"Encrypting {file_name}... ({idx+1}/{len(files)})")
                    
                    # ✅ ĐÚNG: Pass base directory, không phải path đến file
                    encrypt_file(
                        str(file_path),
                        str(ENCRYPTED_DIR)  # Chỉ base dir: /data
                    )
                    
                    progress = 0.1 + (0.5 * (idx + 1) / len(files))
                    self.backup_progress.set(progress)

                encrypt_time = time.time() - encrypt_start
                logger.info(f"✓ Encryption completed in {encrypt_time:.2f}s")
                self.encrypt_time_label.configure(text=f"Encryption time: {encrypt_time:.2f}s")

                # ===== UPLOAD PHASE =====
                upload_start = time.time()
                self.backup_progress.set(0.7)
                logger.info("Uploading to S3...")
                
                # Upload với cấu trúc mới
                encrypted_dir = ENCRYPTED_DIR / "encrypted"
                keys_dir = ENCRYPTED_DIR / "keys"
                metadata_dir = ENCRYPTED_DIR / "metadata"
                
                upload_count = 0
                
                for idx, file_path in enumerate(files):
                    file_name = Path(file_path).name
                    
                    # Upload .enc
                    enc_path = encrypted_dir / f"{file_name}.enc"
                    if enc_path.exists():
                        upload_file_to_s3(str(enc_path), f"encrypted/{enc_path.name}")
                        upload_count += 1
                    
                    # Upload .key.enc
                    key_path = keys_dir / f"{file_name}.key.enc"
                    if key_path.exists():
                        upload_file_to_s3(str(key_path), f"keys/{key_path.name}")
                        upload_count += 1
                    
                    # Upload metadata
                    meta_path = metadata_dir / f"{file_name}.metadata.json"
                    if meta_path.exists():
                        upload_file_to_s3(str(meta_path), f"metadata/{meta_path.name}")
                        upload_count += 1
                    
                    progress = 0.7 + (0.3 * (idx + 1) / len(files))
                    self.backup_progress.set(progress)

                upload_time = time.time() - upload_start
                logger.info(f"✓ Upload completed in {upload_time:.2f}s")
                logger.info(f"✓ Uploaded {upload_count} files to S3")
                self.upload_time_label.configure(text=f"Upload time: {upload_time:.2f}s")

                self.backup_progress.set(1.0)
                total_time = encrypt_time + upload_time
                logger.info(f"=== BACKUP COMPLETED SUCCESSFULLY in {total_time:.2f}s ===")

                messagebox.showinfo(
                    "Success", 
                    f"Backup completed successfully!\n\n"
                    f"Original files: {len(files)}\n"
                    f"Uploaded files: {upload_count}\n"
                    f"Encryption: {encrypt_time:.2f}s\n"
                    f"Upload: {upload_time:.2f}s\n"
                    f"Total: {total_time:.2f}s"
                )

            except Exception as e:
                logger.error(f"Backup failed: {e}", exc_info=True)
                messagebox.showerror("Error", f"Backup failed:\n{str(e)}")
            finally:
                self.backup_progress.set(0)

        threading.Thread(target=worker, daemon=True).start()
    # =====================================================
    # RESTORE TAB - WITH S3 FILE LIST
    # =====================================================
    def show_restore(self):
        self._clear_content()

        main_frame = ctk.CTkScrollableFrame(self.content)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="🔄 Restore - Download & Decrypt",
            font=("Arial", 24, "bold"),
        ).pack(pady=(0, 20))

        if not self.s3_ready or not self.rsa_ready:
            warning = ctk.CTkLabel(
                main_frame,
                text="⚠️ Please configure AWS and RSA keys in Settings first",
                font=("Arial", 14),
                text_color="orange"
            )
            warning.pack(pady=20)
            return

        # S3 File List
        list_frame = ctk.CTkFrame(main_frame)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        ctk.CTkLabel(list_frame, text="Available Backups on S3:", font=("Arial", 14, "bold")).pack(pady=5)

        # Refresh button
        ctk.CTkButton(
            list_frame,
            text="🔄 Refresh List",
            command=self.load_s3_files,
            height=30
        ).pack(pady=5)

        # File list (using Treeview for better display)
        tree_frame = ctk.CTkFrame(list_frame)
        tree_frame.pack(fill="both", expand=True, pady=5)

        # Create Treeview
        columns = ('Filename', 'Size', 'Modified', 'Integrity')
        self.s3_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=10)
        
        self.s3_tree.heading('Filename', text='Filename')
        self.s3_tree.heading('Size', text='Size')
        self.s3_tree.heading('Modified', text='Modified')
        self.s3_tree.heading('Integrity', text='Integrity')
        
        self.s3_tree.column('Filename', width=300)
        self.s3_tree.column('Size', width=100)
        self.s3_tree.column('Modified', width=150)
        self.s3_tree.column('Integrity', width=100)
        
        self.s3_tree.pack(side="left", fill="both", expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.s3_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.s3_tree.configure(yscrollcommand=scrollbar.set)

        # Restore button
        ctk.CTkButton(
            main_frame,
            text="📥 Download & Decrypt Selected",
            command=self.restore_selected,
            height=40
        ).pack(pady=10)

        # Load files on show
        self.load_s3_files()

    def load_s3_files(self):
        """Load list of files from S3"""
        def worker():
            try:
                logger.info("Loading S3 file list...")
                
                bucket = get_bucket_name()
                if not bucket:
                    messagebox.showerror("Error", "S3 bucket not configured")
                    return

                s3 = boto3.client("s3")
                
                # List encrypted files
                response = s3.list_objects_v2(Bucket=bucket, Prefix="encrypted/")
                
                # Clear existing items
                for item in self.s3_tree.get_children():
                    self.s3_tree.delete(item)
                
                if 'Contents' not in response:
                    logger.info("No files found on S3")
                    return
                
                # Process each file
                for obj in response['Contents']:
                    if not obj['Key'].endswith('.enc'):
                        continue
                    
                    filename = obj['Key'].replace('encrypted/', '')
                    size_mb = obj['Size'] / (1024 * 1024)
                    modified = obj['LastModified'].strftime('%Y-%m-%d %H:%M')
                    
                    # Check integrity on S3
                    base_name = filename.replace('.enc', '')
                    try:
                        from app.storage.s3_download import verify_on_s3
                        integrity = "✓ OK" if verify_on_s3(base_name) else "✗ FAIL"
                    except:
                        integrity = "Unknown"
                    
                    self.s3_tree.insert('', 'end', values=(
                        filename,
                        f"{size_mb:.2f} MB",
                        modified,
                        integrity
                    ))
                
                logger.info(f"Loaded {len(response['Contents'])} files from S3")
                
            except Exception as e:
                logger.error(f"Failed to load S3 files: {e}", exc_info=True)
                messagebox.showerror("Error", f"Failed to load S3 files:\n{str(e)}")

        threading.Thread(target=worker, daemon=True).start()

    def restore_selected(self):
        """Restore selected files from S3"""
        selected = self.s3_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select files to restore")
            return

        # Get password
        if not self.rsa_password:
            dialog = ctk.CTkInputDialog(
                text="Enter RSA password:",
                title="Decrypt Files"
            )
            self.rsa_password = dialog.get_input()
            
            if not self.rsa_password:
                return

        def worker():
            try:
                logger.info("Starting restore process...")
                
                for item in selected:
                    values = self.s3_tree.item(item)['values']
                    filename = values[0].replace('.enc', '')
                    
                    logger.info(f"Downloading {filename}...")
                    
                    # Download
                    download_file_pair(filename)
                    
                    # Decrypt
                    enc_file = DOWNLOADED_DIR / f"{filename}.enc"
                    if enc_file.exists():
                        logger.info(f"Decrypting {filename}...")
                        decrypt_file(enc_file, self.rsa_password)
                
                logger.info("✓ Restore completed")
                messagebox.showinfo("Success", f"Successfully restored {len(selected)} file(s)!")
                
            except Exception as e:
                logger.error(f"Restore failed: {e}", exc_info=True)
                messagebox.showerror("Error", f"Restore failed:\n{str(e)}")

        threading.Thread(target=worker, daemon=True).start()

    # =====================================================
    # VERIFY TAB - WITH FILE SELECTION & CHECKSUM
    # =====================================================
    def show_verify(self):
        self._clear_content()

        main_frame = ctk.CTkScrollableFrame(self.content)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="✅ Verify Integrity",
            font=("Arial", 24, "bold"),
        ).pack(pady=(0, 20))

        # Verify all button
        ctk.CTkButton(
            main_frame,
            text="🔍 Verify All Local Files",
            command=self.verify_all_local,
            height=40
        ).pack(pady=10)

        # File selection for individual verification
        select_frame = ctk.CTkFrame(main_frame)
        select_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(select_frame, text="Or verify individual file:", font=("Arial", 13, "bold")).pack(pady=5)

        ctk.CTkButton(
            select_frame,
            text="📄 Select File to Verify",
            command=self.select_file_to_verify,
            height=35
        ).pack(pady=5)

        # Checksum display
        self.checksum_frame = ctk.CTkFrame(main_frame)
        self.checksum_frame.pack(fill="both", expand=True, pady=10)
        
        ctk.CTkLabel(self.checksum_frame, text="Checksum Details:", font=("Arial", 13, "bold")).pack(pady=5)

        self.checksum_text = ctk.CTkTextbox(self.checksum_frame, height=200, font=("Courier", 10))
        self.checksum_text.pack(fill="both", expand=True, pady=5)

    def verify_all_local(self):
        """Verify all local files"""
        def worker():
            try:
                logger.info("Verifying all local files...")
                
                results = verify_all_files()
                
                total = results.get('total', 0)
                passed = results.get('passed', 0)
                failed = results.get('failed', 0)
                
                if total == 0:
                    messagebox.showwarning("No Files", "No encrypted files found to verify.")
                elif failed == 0:
                    logger.info(f"✓ All {passed} files verified successfully")
                    messagebox.showinfo(
                        "Success", 
                        f"All {passed} files verified successfully!\n\n"
                        f"Total: {total}\n"
                        f"Passed: {passed}\n"
                        f"Failed: {failed}"
                    )
                else:
                    logger.warning(f"Verification completed with {failed} failures")
                    
                    details = "\n".join([
                        f"{'✓' if f['status'] == 'PASS' else '✗'} {f['file']}"
                        for f in results.get('files', [])[:10]
                    ])
                    
                    messagebox.showwarning(
                        "Verification Issues",
                        f"Verification completed with issues:\n\n"
                        f"Total: {total}\n"
                        f"Passed: {passed}\n"
                        f"Failed: {failed}\n\n"
                        f"First 10 files:\n{details}\n\n"
                        f"Check logs for details."
                    )
                
            except Exception as e:
                logger.error(f"Verification failed: {e}", exc_info=True)
                messagebox.showerror("Error", f"Verification failed:\n{str(e)}")

        threading.Thread(target=worker, daemon=True).start()

    def select_file_to_verify(self):
        """Select and verify individual file"""
        file_path = filedialog.askopenfilename(
            title="Select encrypted file to verify",
            initialdir=ENCRYPTED_DIR,
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if not file_path:
            return

        def worker():
            try:
                logger.info(f"Verifying {Path(file_path).name}...")
                
                # Verify
                result = verify_local(file_path)
                
                # Get metadata
                base_name = Path(file_path).name.replace('.enc', '')
                meta_path = Path(file_path).parent / f"{base_name}.metadata.json"
                
                # Calculate checksum
                actual_checksum = sha256_file(file_path)
                
                # Load expected checksum
                expected_checksum = "N/A"
                if meta_path.exists():
                    with open(meta_path, 'r') as f:
                        metadata = json.load(f)
                        expected_checksum = metadata.get('ciphertext_sha256', 'N/A')
                
                # Display results
                self.checksum_text.delete("1.0", "end")
                
                output = f"""
                File: {Path(file_path).name}
                Status: {'✓ PASS' if result else '✗ FAIL'}

                === CHECKSUMS ===
                Expected (from metadata):
                {expected_checksum}

                Actual (calculated):
                {actual_checksum}

                Match: {'YES' if expected_checksum == actual_checksum else 'NO'}

                === FILE INFO ===
                Size: {Path(file_path).stat().st_size / (1024*1024):.2f} MB
                Modified: {datetime.fromtimestamp(Path(file_path).stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
                """
                self.checksum_text.insert("1.0", output.strip())
                
                if result:
                    logger.info("✓ Verification passed")
                else:
                    logger.error("✗ Verification failed")
                
            except Exception as e:
                logger.error(f"Verification error: {e}", exc_info=True)
                messagebox.showerror("Error", f"Verification error:\n{str(e)}")

        threading.Thread(target=worker, daemon=True).start()

    def verify_encrypted_file(encrypted_path, password):
        """Verify với path resolution đúng"""
        encrypted_path = Path(encrypted_path)
    
    # Determine base directory
        if encrypted_path.parent.name == "encrypted":
            base_dir = encrypted_path.parent.parent
        else:
            base_dir = encrypted_path.parent
    
        # Construct paths
        base_name = encrypted_path.name.replace('.enc', '')
        metadata_dir = base_dir / "metadata"
        keys_dir = base_dir / "keys"
        
        meta_path = metadata_dir / f"{base_name}.metadata.json"
        key_path = keys_dir / f"{base_name}.key.enc"
        
        # Check files exist
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata not found: {meta_path}")
        
        # Load and verify metadata
        with open(meta_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        # Verify checksum
        current_checksum = sha256_file(str(encrypted_path))
        expected_checksum = metadata.get('ciphertext_sha256')
        
        if current_checksum != expected_checksum:
            raise ValueError("Checksum mismatch!")
        
        return True
    # =====================================================
    # LOG POLLER
    # =====================================================
    def _poll_log(self):
        """Poll log queue and update UI"""
        try:
            while not log_queue.empty():
                msg = log_queue.get_nowait()
                self.log_box.insert("end", msg + "\n")
                self.log_box.see("end")
        except:
            pass
            
        self.after(200, self._poll_log)

# =========================================================
# ENTRY POINT
# =========================================================
def main():
    # Set theme
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    # Run app
    app = BackupApp()
    app.mainloop()

if __name__ == "__main__":
    main()