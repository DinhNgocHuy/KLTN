from pathlib import Path

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def base_name(path):
    return Path(path).stem  # "a.txt.enc" → "a.txt"