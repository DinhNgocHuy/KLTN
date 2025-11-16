import hashlib

def file_hash(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

if __name__ == "__main__":
    original = "../data/original/quocphong_ss2.docx"
    restored = "../data/restored/quocphong_ss2.docx"
    if file_hash(original) == file_hash(restored):
        print("Data is integrity (hash match)")
    else:
        print("Data has been altered")