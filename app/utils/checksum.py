import hashlib

def sha256_file(path, chunk=1024*1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for data in iter(lambda: f.read(chunk), b""):
            h.update(data)
    return h.hexdigest()