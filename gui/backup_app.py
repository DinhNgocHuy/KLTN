import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import os

from app.crypto.encryption import encrypt_file
from app.crypto.decryption import decrypt_file
from app.storage.s3_upload import upload_all_encrypted
from app.storage.s3_download import download_file_pair
from app.storage.verify_integrity import verify_integrity
from app.crypto.key_management import rotate_keys
from app.settings import DATA_DIR, KEY_DIR


# ============================================================
# GUI CLASS
# ============================================================
class BackupApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Secure Backup System – AES-GCM + RSA + S3")
        self.geometry("860x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Selected file
        self.input_file = None

        # Layout
        self.create_ui()

    # --------------------------------------------------------
    # LOGGING PANEL
    # --------------------------------------------------------
    def log(self, text: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{text}\n")
        self.log_box.configure(state="disabled")
        self.log_box.see("end")

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------
    def create_ui(self):

        # LEFT PANEL
        left = ctk.CTkFrame(self, width=300, corner_radius=10)
        left.pack(side="left", fill="y", padx=10, pady=10)

        title = ctk.CTkLabel(left, text="Backup Controls", font=("Arial", 22, "bold"))
        title.pack(pady=15)

        # Choose File
        choose_btn = ctk.CTkButton(left, text="Choose File", command=self.choose_file)
        choose_btn.pack(pady=10)

        self.file_label = ctk.CTkLabel(left, text="No file selected", wraplength=250)
        self.file_label.pack(pady=10)

        # Encrypt + Upload
        enc_btn = ctk.CTkButton(left, text="Encrypt & Upload", command=self.run_encrypt_upload)
        enc_btn.pack(pady=10)

        # Download + Decrypt
        dec_btn = ctk.CTkButton(left, text="Download & Decrypt", command=self.run_download_decrypt)
        dec_btn.pack(pady=10)

        # Verify
        verify_btn = ctk.CTkButton(left, text="Verify Integrity", command=self.run_verify)
        verify_btn.pack(pady=10)

        # Rotate Keys
        rotate_btn = ctk.CTkButton(left, text="Rotate RSA Keys", command=self.run_rotate)
        rotate_btn.pack(pady=10)

        # RIGHT PANEL — LOG BOX
        right = ctk.CTkFrame(self, corner_radius=10)
        right.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(right, text="System Log", font=("Arial", 20, "bold")).pack(pady=10)

        self.log_box = ctk.CTkTextbox(right, state="disabled", font=("Consolas", 13))
        self.log_box.pack(fill="both", expand=True, pady=10)

    # --------------------------------------------------------
    # ACTIONS
    # --------------------------------------------------------

    def choose_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.input_file = file
            self.file_label.configure(text=file)
            self.log(f"[SELECT] {file}")

    # -----------------------------------
    # Encrypt + Upload
    # -----------------------------------
    def run_encrypt_upload(self):
        if not self.input_file:
            messagebox.showerror("Error", "Please choose a file first.")
            return
        threading.Thread(target=self.encrypt_upload).start()

    def encrypt_upload(self):
        file = self.input_file
        basename = os.path.basename(file)

        enc_path = f"{DATA_DIR}/encrypted/{basename}.enc"
        key_path = f"{DATA_DIR}/encrypted/{basename}.key.enc"

        self.log(f"Encrypting: {file}")

        # Ask for RSA password
        password = ctk.CTkInputDialog(text="Enter RSA password:", title="Password").get_input()

        try:
            encrypt_file(file, enc_path, key_path, password=password)
            self.log(f"✓ Encryption complete: {enc_path}")

            upload_all_encrypted(enc_path, key_path)
            self.log("✓ Uploaded to S3 successfully")

        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            messagebox.showerror("Error", str(e))

    # -----------------------------------
    # Download + Decrypt
    # -----------------------------------
    def run_download_decrypt(self):
        threading.Thread(target=self.download_decrypt).start()

    def download_decrypt(self):
        filename = ctk.CTkInputDialog(text="Enter filename (without .enc):", title="Download").get_input()

        enc_local, key_local, _ = download_file_pair(filename)

        if not enc_local:
            self.log("Download failed")
            return

        password = ctk.CTkInputDialog(text="Enter RSA password:", title="Decrypt").get_input()

        output_path = f"{DATA_DIR}/restored/{filename}"

        decrypt_file(enc_local, key_local, output_path, password)
        self.log(f"✓ File decrypted → {output_path}")

    # -----------------------------------
    # Verify Integrity
    # -----------------------------------
    def run_verify(self):
        threading.Thread(target=self.verify).start()

    def verify(self):
        filename = ctk.CTkInputDialog(text="Enter filename:", title="Verify").get_input()

        ok = verify_integrity(filename)
        if ok:
            self.log(f"✓ Integrity OK → {filename}")
        else:
            self.log(f"✗ FAILED → {filename}")

    # -----------------------------------
    # Rotate RSA Keys
    # -----------------------------------
    def run_rotate(self):
        threading.Thread(target=self.rotate).start()

    def rotate(self):
        old_pass = ctk.CTkInputDialog(text="Enter OLD RSA password:", title="RSA Rotation").get_input()
        if not old_pass:
            return

        self.log("Rotating RSA keys…")
        ok = rotate_keys(old_pass)
        if ok:
            self.log("✓ RSA key rotation completed")
        else:
            self.log("✗ Rotation failed")


# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    app = BackupApp()
    app.mainloop()