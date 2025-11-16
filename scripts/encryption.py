import os
import glob
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =========================
# CONFIG
# =========================
KEY_DIR = "../keys"
DATA_DIR = "../data"
AES_KEY_SIZE = 32  # 256-bit AES key
IV_SIZE = 16       # 128-bit IV (nonce)


# =========================
# 1️⃣ TẠO CẶP KHÓA RSA (Public/Private)
# =========================
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    os.makedirs(KEY_DIR, exist_ok=True)

    with open(f"{KEY_DIR}/rsa_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(f"{KEY_DIR}/rsa_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Generated RSA key pair (rsa_private.pem, rsa_public.pem)")


# =========================
# 2️⃣ TẢI KHÓA RSA TỪ FILE
# =========================
def load_rsa_keys():
    with open(f"{KEY_DIR}/rsa_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(f"{KEY_DIR}/rsa_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key


# =========================
# 3️⃣ MÃ HÓA 1 FILE (AES + RSA)
# =========================
def encrypt_file(input_path, encrypted_path, encrypted_key_path):
    from os import urandom
    start_time = time.perf_counter()

    aes_key = urandom(AES_KEY_SIZE)
    iv = urandom(IV_SIZE)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Mã hóa AES key bằng RSA public key
    _, public_key = load_rsa_keys()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)
    with open(encrypted_path, "wb") as f:
        f.write(iv + ciphertext)  # prepend IV

    with open(encrypted_key_path, "wb") as f:
        f.write(encrypted_aes_key)

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time

    print(f"Encrypted: {os.path.basename(input_path)} in {elapsed_time:.2f} seconds")
    print(f"   → Data: {encrypted_path}")
    print(f"   → AES key (encrypted): {encrypted_key_path}")


# =========================
# 4️⃣ GIẢI MÃ 1 FILE (RSA + AES)
# =========================
def decrypt_file(encrypted_path, encrypted_key_path, output_path):
    start_time = time.perf_counter()
    private_key, _ = load_rsa_keys()

    with open(encrypted_key_path, "rb") as f:
        encrypted_aes_key = f.read()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    with open(encrypted_path, "rb") as f:
        data = f.read()
        iv, ciphertext = data[:IV_SIZE], data[IV_SIZE:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    elapsed = time.perf_counter() - start_time
    print(f"Thời gian giải mã: {elapsed:.3f} giây")

    print(f"Decrypted: {os.path.basename(encrypted_path)} → {output_path}")


# =========================
# 5️⃣ MÃ HÓA TOÀN BỘ FILE TRONG THƯ MỤC
# =========================
def encrypt_all_in_folder(input_folder, encrypted_folder):
    os.makedirs(encrypted_folder, exist_ok=True)
    files = [f for f in glob.glob(os.path.join(input_folder, "**/*.*"), recursive=True)]

    if not files:
        print("Không có file nào trong thư mục:", input_folder)
        return

    print(f"Bắt đầu mã hóa {len(files)} file trong {input_folder} ...")
    for file_path in files:
        file_name = os.path.basename(file_path)
        encrypted_path = os.path.join(encrypted_folder, f"{file_name}.enc")
        encrypted_key_path = os.path.join(encrypted_folder, f"{file_name}.key.enc")
        try:
            encrypt_file(file_path, encrypted_path, encrypted_key_path)
        except Exception as e:
            print(f"Error when encrypting {file_name}: {e}")
    print("Completed encrypting all files.")


# =========================
# 6️⃣ DECRYPT ALL FILES IN FOLDER
# =========================
def decrypt_all_in_folder(encrypted_folder, restored_folder):
    os.makedirs(restored_folder, exist_ok=True)
    enc_files = glob.glob(os.path.join(encrypted_folder, "*.enc"))

    if not enc_files:
        print("No encrypted files in:", encrypted_folder)
        return

    print(f"Starting to decrypt {len(enc_files)} files in {encrypted_folder} ...")
    for enc_file in enc_files:
        base_name = os.path.basename(enc_file).replace(".enc", "")
        enc_key_file = os.path.join(encrypted_folder, f"{base_name}.key.enc")
        output_path = os.path.join(restored_folder, base_name)

        if not os.path.exists(enc_key_file):
            print(f"Skipping {base_name}: key file not found.")
            continue

        try:
            decrypt_file(enc_file, enc_key_file, output_path)
        except Exception as e:
            print(f"Error when decrypting {base_name}: {e}")

    print("Completed decrypting all files.")


# =========================
# 7️⃣ MAIN – CHẠY TRỰC TIẾP
# =========================
if __name__ == "__main__":
    import sys

    original_folder = f"{DATA_DIR}/original"
    encrypted_folder = f"{DATA_DIR}/encrypted"
    restored_folder = f"{DATA_DIR}/restored"

    # Nếu chưa có RSA key thì tạo mới
    if not os.path.exists(f"{KEY_DIR}/rsa_private.pem"):
        generate_rsa_keys()

    # Cờ dòng lệnh
    args = sys.argv[1:] if len(sys.argv) > 1 else []

    if "--all" in args:
        encrypt_all_in_folder(original_folder, encrypted_folder)
    elif "--decrypt-all" in args:
        decrypt_all_in_folder(encrypted_folder, restored_folder)
    else:
        # Demo mã hóa & giải mã 1 file
        sample_file = f"{original_folder}/quocphong_ss2.docx"
        enc_file = f"{encrypted_folder}/quocphong_ss2.docx.enc"
        enc_key_file = f"{encrypted_folder}/quocphong_ss2.docx.key.enc"
        restored = f"{restored_folder}/quocphong_ss2.docx"

        encrypt_file(sample_file, enc_file, enc_key_file)
        decrypt_file(enc_file, enc_key_file, restored)
