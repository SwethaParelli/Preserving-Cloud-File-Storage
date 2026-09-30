import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration management class."""
    
    # Flask Security
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    DEBUG = os.getenv("FLASK_ENV", "development") == "development"
    PORT = int(os.getenv("PORT", 5000))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))  # 50MB default
    
    # MongoDB Settings
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/privacy_storage_db")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "privacy_storage_db")
    
    # AES-256 Key Configuration
    # Needs to be 32 bytes (256 bits).
    RAW_ENC_KEY = os.getenv("MASTER_ENCRYPTION_KEY", "")
    if RAW_ENC_KEY:
        try:
            if len(RAW_ENC_KEY) == 64:
                MASTER_ENCRYPTION_KEY = bytes.fromhex(RAW_ENC_KEY)
            else:
                # If raw string, pad or slice to 32 bytes
                MASTER_ENCRYPTION_KEY = RAW_ENC_KEY.encode('utf-8').ljust(32, b'0')[:32]
        except ValueError:
            MASTER_ENCRYPTION_KEY = RAW_ENC_KEY.encode('utf-8').ljust(32, b'0')[:32]
    else:
        # Fallback to a deterministic demo key or newly generated
        MASTER_ENCRYPTION_KEY = b"CNS_SECURE_AES_256_GCM_KEY_2026!" # 32 bytes exactly
    
    # Cloud Storage (AWS S3 vs Local Encrypted Storage)
    USE_S3 = os.getenv("USE_S3", "false").lower() in ("true", "1", "yes")
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "privacy-preserving-file-storage-bucket")
    
    # Local encrypted storage directory
    LOCAL_ENCRYPTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encrypted_storage")
    
    # Ensure local encrypted storage directory exists
    os.makedirs(LOCAL_ENCRYPTED_DIR, exist_ok=True)
