import logging
from pathlib import Path
from app.core.settings import LOG_DIR

def setup_logger(name: str, log_file: str, level=logging.INFO) -> logging.Logger:
    """Setup logger với file và console handlers"""
    # Tạo log directory
    log_path = Path(LOG_DIR) / log_file
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()  # QUAN TRỌNG: Clear existing handlers
    
    # File handler
    file_handler = logging.FileHandler(
        log_path, 
        mode='a',
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Initialize all loggers
encryption_logger = setup_logger('encryption', 'crypto/encryption.log')
decryption_logger = setup_logger('decryption', 'crypto/decryption.log')
key_logger = setup_logger('key_management', 'crypto/key_management.log')
s3_upload_logger = setup_logger('s3_upload', 'storage/s3_upload.log')
s3_download_logger = setup_logger('s3_download', 'storage/s3_download.log')
system_logger = setup_logger('system', 'system/system.log')
error_logger = setup_logger('error', 'error/error.log', level=logging.ERROR)