import json
from pathlib import Path
from app.core.logging_config import system_logger, error_logger

DEFAULT_CONFIG = {
    "aws": {},
    "auto_backup": {
        "enabled": True,
        "watch_folder": ""
    }
}

CONFIG_FILE = Path("config.json")


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        system_logger.warning(
            "config.json not found. Creating default config."
        )
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def update_config(new_data: dict):
    config = load_config()
    config.update(new_data)
    save_config(config)
