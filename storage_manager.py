"""
Storage Manager Module
----------------------
Manages storage operations for encrypted file payloads.
Supports AWS S3 Cloud Storage and Local Encrypted Storage (offline/fallback mode).
Plaintext files are NEVER stored on disk or uploaded to cloud storage.
"""

import os
import io
import logging
from config import Config

logger = logging.getLogger(__name__)

class StorageManager:
    def __init__(self):
        self.use_s3 = Config.USE_S3
        self.s3_client = None
        self.bucket_name = Config.S3_BUCKET_NAME
        self.local_dir = Config.LOCAL_ENCRYPTED_DIR
        
        # Initialize S3 client if configured
        if self.use_s3 and Config.AWS_ACCESS_KEY_ID and Config.AWS_SECRET_ACCESS_KEY:
            try:
                import boto3
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
                    region_name=Config.AWS_REGION
                )
                logger.info("AWS S3 client initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize AWS S3 client: {e}. Falling back to local encrypted storage.")
                self.s3_client = None
                self.use_s3 = False

    def get_storage_mode(self) -> str:
        """Returns 'AWS S3 Cloud' or 'Local Encrypted Storage'."""
        if self.use_s3 and self.s3_client is not None:
            return "AWS S3 Cloud"
        return "Local Encrypted Storage"

    def save_encrypted_file(self, file_key: str, encrypted_bytes: bytes) -> dict:
        """
        Store ciphertext payload into configured storage.
        
        :param file_key: Unique identifier / storage key (e.g. user_id/uuid-filename.enc)
        :param encrypted_bytes: The AES-256-GCM encrypted binary data
        :return: dict with storage details
        """
        if self.use_s3 and self.s3_client is not None:
            try:
                # Stream ciphertext into S3
                file_obj = io.BytesIO(encrypted_bytes)
                self.s3_client.upload_fileobj(
                    file_obj,
                    self.bucket_name,
                    file_key,
                    ExtraArgs={"ContentType": "application/octet-stream"}
                )
                logger.info(f"Encrypted file saved to AWS S3 bucket {self.bucket_name}: {file_key}")
                return {
                    "storage_type": "s3",
                    "storage_path": f"s3://{self.bucket_name}/{file_key}",
                    "s3_key": file_key
                }
            except Exception as ex:
                logger.error(f"Failed to upload to S3: {ex}. Falling back to local encrypted storage.")
                # Fall through to local storage
        
        # Local encrypted storage mode
        if not file_key.endswith(".enc"):
            file_key_path = f"{file_key}.enc"
        else:
            file_key_path = file_key
            
        local_filepath = os.path.join(self.local_dir, file_key_path)
        os.makedirs(os.path.dirname(local_filepath), exist_ok=True)
        
        with open(local_filepath, "wb") as f:
            f.write(encrypted_bytes)
        
        logger.info(f"Encrypted file saved to local encrypted directory: {local_filepath}")
        return {
            "storage_type": "local_encrypted",
            "storage_path": local_filepath,
            "s3_key": file_key
        }

    def get_encrypted_file(self, file_key: str, storage_type: str = "local_encrypted") -> bytes:
        """
        Retrieve encrypted ciphertext from S3 or local directory.
        
        :param file_key: Storage key / file identifier
        :param storage_type: 's3' or 'local_encrypted'
        :return: Ciphertext bytes
        """
        if storage_type == "s3" and self.s3_client is not None:
            try:
                file_obj = io.BytesIO()
                self.s3_client.download_fileobj(self.bucket_name, file_key, file_obj)
                file_obj.seek(0)
                return file_obj.read()
            except Exception as ex:
                logger.error(f"S3 download failed for key {file_key}: {ex}")
                raise FileNotFoundError(f"Could not retrieve file from AWS S3: {ex}")
        
        # Local retrieval
        file_key_path = file_key if file_key.endswith(".enc") else f"{file_key}.enc"
        local_filepath = os.path.join(self.local_dir, file_key_path)
        
        if not os.path.exists(local_filepath):
            # Try exact path if file_key was already full path or without .enc
            if os.path.exists(os.path.join(self.local_dir, file_key)):
                local_filepath = os.path.join(self.local_dir, file_key)
            elif os.path.exists(file_key):
                local_filepath = file_key
            else:
                raise FileNotFoundError(f"Encrypted file not found on storage: {file_key}")
                
        with open(local_filepath, "rb") as f:
            return f.read()

    def delete_encrypted_file(self, file_key: str, storage_type: str = "local_encrypted") -> bool:
        """
        Delete ciphertext from S3 or local storage.
        
        :param file_key: Storage key / file identifier
        :param storage_type: 's3' or 'local_encrypted'
        :return: True if successful
        """
        success = False
        if storage_type == "s3" and self.s3_client is not None:
            try:
                self.s3_client.delete_object(Bucket=self.bucket_name, Key=file_key)
                success = True
            except Exception as ex:
                logger.error(f"Failed to delete object from S3: {ex}")
        
        # Local delete
        file_key_path = file_key if file_key.endswith(".enc") else f"{file_key}.enc"
        local_filepath = os.path.join(self.local_dir, file_key_path)
        if not os.path.exists(local_filepath) and os.path.exists(os.path.join(self.local_dir, file_key)):
            local_filepath = os.path.join(self.local_dir, file_key)
            
        if os.path.exists(local_filepath):
            try:
                os.remove(local_filepath)
                success = True
            except Exception as ex:
                logger.error(f"Failed to remove local file: {ex}")
                
        return success

# Global singleton storage instance
storage = StorageManager()
