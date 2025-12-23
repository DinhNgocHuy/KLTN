import os
import threading
import queue
import logging
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

import customtkinter as ctk
from tkinter import filedialog

from app.crypto.encryption import encrypt_all_in_folder
from app.crypto.key_management import rotate_keys
from app.crypto.rsa_utils import (
    generate_rsa_keys,
    get_current_rsa_version,
    set_current_rsa_version,
)
from app.core.settings import DATA_DIR
from app.storage.s3_upload import upload_all_encrypted

# =========================
# CONSTANT
# =========================
DEFAULT_REGION = "ap-southeast-1"
LOG_DIR = Path(DATA_DIR).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# =========================
# LOGGING (GLOBAL)
# =========================
log_queue = queue.Queue()

class UILogHandler(logging.Handler):
    def emit(self, record):
        log_queue.put(self.format(record))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "app.log"),
        UILogHandler(),
    ],
)

# =========================
# MAIN APP
# =========================
class BackupApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Secure Backup System – AES-GCM + RSA + S3")
        self.geometry("1100x700")

        # ===== SYSTEM STATE =====
        self.s3_ready = False
        self.rsa_ready = False
        self.selected_folder = None

        # ===== UI =====
        self._build_layout()
        self.after(200, self._poll_log)

    # =========================
    # LAYOUT
    # =========================
    def _build_layout(self):
        self.sidebar = ctk.CTkFrame(self, width=180)
        self.sidebar.pack(side="left", fill="y")

        self.content = ctk.CTkFrame(self)
        self.content.pack(side="right", expand=True, fill="both")

        ctk.CTkLabel(
            self.sidebar,
            text="Secure Backup",
            font=("Arial", 18, "bold"),
        ).pack(pady=20)

        for name, cmd in [
            ("Backup", self.show_backup),
            ("Restore", self.show_restore),
            ("Verify", self.show_verify),
            ("Settings", self.show_settings),
        ]:
            ctk.CTkButton(self.sidebar, text=name, command=cmd).pack(
                pady=6, padx=10, fill="x"
            )

        self.log_box = ctk.CTkTextbox(self.content, height=200)
        self.log_box.pack(side="bottom", fill="x", padx=10, pady=10)

        self.show_settings()

    def _clear_content(self):
        for w in self.content.winfo_children():
            if w is not self.log_box:
                w.destroy()

    # =========================
    # BACKUP TAB
    # =========================
    def show_backup(self):
        self._clear_content()

        ctk.CTkLabel(
            self.content,
            text="Backup – Encrypt & Upload (Folder)",
            font=("Arial", 20, "bold"),
        ).pack(pady=20)

        ctk.CTkButton(
            self.content,
            text="Choose Folder",
            command=self.choose_folder,
        ).pack(pady=10)

        self.folder_label = ctk.CTkLabel(
            self.content,
            text="No folder selected",
        )
        self.folder_label.pack()

        self.btn_backup = ctk.CTkButton(
            self.content,
            text="Encrypt & Upload",
            command=self.run_backup,
        )
        self.btn_backup.pack(pady=20)

        if self.s3_ready and self.rsa_ready:
            self.btn_backup.configure(state="normal")
        else:
            self.btn_backup.configure(state="disabled")

    def choose_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.selected_folder = path
            self.folder_label.configure(text=path)
            logging.info(f"Selected folder: {path}")

    def run_backup(self):
        if not self.selected_folder:
            logging.error("No folder selected")
            return

        def worker():
            try:
                logging.info("Encrypting folder...")
                encrypt_all_in_folder(self.selected_folder)
                logging.info("Uploading encrypted data to S3...")
                upload_all_encrypted()
                logging.info("Backup completed successfully")
            except Exception:
                logging.exception("Backup failed")

        threading.Thread(target=worker, daemon=True).start()

    # =========================
    # SETTINGS TAB
    # =========================
    def show_settings(self):
        self._clear_content()

        ctk.CTkLabel(
            self.content,
            text="Settings & Connectivity",
            font=("Arial", 20, "bold"),
        ).pack(pady=20)

        self.aws_key = ctk.CTkEntry(self.content, placeholder_text="AWS Access Key")
        self.aws_key.pack(fill="x", padx=80, pady=5)

        self.aws_secret = ctk.CTkEntry(
            self.content,
            placeholder_text="AWS Secret Key",
            show="*",
        )
        self.aws_secret.pack(fill="x", padx=80, pady=5)

        self.bucket_entry = ctk.CTkEntry(
            self.content,
            placeholder_text="S3 Bucket Name",
        )
        self.bucket_entry.pack(fill="x", padx=80, pady=5)

        ctk.CTkButton(
            self.content,
            text="Connect / Init S3",
            command=self.init_s3,
        ).pack(pady=10)

        ctk.CTkLabel(
            self.content,
            text=f"RSA Key Directory:\n{Path(DATA_DIR).parent / 'keys'}",
        ).pack(pady=20)

        ctk.CTkButton(
            self.content,
            text="Generate RSA Key (v1)",
            command=self.init_rsa,
        ).pack(pady=5)

        ctk.CTkButton(
            self.content,
            text="Rotate RSA Key",
            command=self.rotate_rsa,
        ).pack(pady=5)

    def init_s3(self):
        try:
            os.environ["AWS_ACCESS_KEY_ID"] = self.aws_key.get().strip()
            os.environ["AWS_SECRET_ACCESS_KEY"] = self.aws_secret.get().strip()
            bucket = self.bucket_entry.get().strip()

            if not bucket:
                raise ValueError("Bucket name is empty")

            s3 = boto3.client("s3", region_name=DEFAULT_REGION)

            try:
                s3.head_bucket(Bucket=bucket)
                logging.info(f"S3 bucket ready: {bucket}")
            except ClientError:
                s3.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={
                        "LocationConstraint": DEFAULT_REGION
                    },
                )
                logging.info(f"S3 bucket created: {bucket}")

            os.environ["AWS_S3_BUCKET"] = bucket
            self.s3_ready = True

        except Exception:
            self.s3_ready = False
            logging.exception("S3 init failed")

    def init_rsa(self):
        try:
            get_current_rsa_version()
            self.rsa_ready = True
            logging.info("RSA already initialized")
            return
        except Exception:
            pass

        pw = ctk.CTkInputDialog(
            text="Password for RSA v1 (min 6 chars):",
            title="RSA",
        ).get_input()

        if not pw or len(pw) < 6:
            logging.error("Invalid RSA password")
            return

        generate_rsa_keys(pw, "v1")
        set_current_rsa_version("v1")
        self.rsa_ready = True
        logging.info("RSA v1 generated")

    def rotate_rsa(self):
        pw = ctk.CTkInputDialog(
            text="Old RSA password:",
            title="Rotate RSA",
        ).get_input()

        if pw:
            rotate_keys(pw)

    # =========================
    # OTHER TABS (PLACEHOLDER)
    # =========================
    def show_restore(self):
        self._clear_content()
        ctk.CTkLabel(self.content, text="Restore – TODO").pack(pady=50)

    def show_verify(self):
        self._clear_content()
        ctk.CTkLabel(self.content, text="Verify – TODO").pack(pady=50)

    # =========================
    # LOG POLLING
    # =========================
    def _poll_log(self):
        while not log_queue.empty():
            self.log_box.insert("end", log_queue.get() + "\n")
            self.log_box.see("end")
        self.after(200, self._poll_log)


if __name__ == "__main__":
    app = BackupApp()
    app.mainloop()
