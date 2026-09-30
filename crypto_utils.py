"""
Cryptographic Utilities Module
------------------------------
This module provides military-grade encryption, hashing, and token generation:
1. AES-256-GCM authenticated encryption & decryption (AEAD).
2. SHA-256 cryptographic hashing for file integrity verification.
3. bcrypt password hashing and verification.
4. Cryptographically secure random token and nonce generation.
"""

import os
import hashlib
import hmac
import secrets
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import Config

def hash_password(plaintext_password: str) -> str:
    """
    Hash a user password using bcrypt with a secure salt.
    Never stores plaintext passwords.
    
    :param plaintext_password: Raw string password
    :return: Decoded UTF-8 bcrypt hash string
    """
    if not plaintext_password:
        raise ValueError("Password cannot be empty")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(plaintext_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    
    :param plaintext_password: Raw string password
    :param hashed_password: Stored bcrypt hash string
    :return: True if match, False otherwise
    """
    if not plaintext_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plaintext_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def calculate_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 hash of binary data.
    Used for verifying file integrity before encryption and after decryption.
    
    :param data: Raw byte payload
    :return: Hexadecimal string digest (64 characters)
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def verify_sha256_integrity(data: bytes, expected_hash: str) -> bool:
    """
    Verify the integrity of decrypted binary data against the original SHA-256 hash.
    Uses constant-time comparison to prevent timing attacks.
    
    :param data: Decrypted raw byte payload
    :param expected_hash: Original SHA-256 hex string stored during upload
    :return: True if exact match, False if corrupted/tampered
    """
    actual_hash = calculate_sha256(data)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())

def generate_nonce(length: int = 12) -> bytes:
    """
    Generate a cryptographically secure random nonce/IV for AES-GCM.
    Standard recommendation for AES-GCM is 12 bytes (96 bits) for optimal performance & security.
    A fresh random nonce MUST be generated for every encryption operation.
    
    :param length: Byte length of nonce (default 12)
    :return: Random bytes
    """
    return os.urandom(length)

def encrypt_file_data(plaintext_bytes: bytes, key: bytes = None, associated_data: bytes = None) -> tuple[bytes, bytes, str]:
    """
    Encrypt file data using AES-256-GCM.
    
    GCM provides both Confidentiality and Authenticity:
    - AES-256 encrypts the data.
    - An authentication tag is appended automatically by AESGCM, which detects any ciphertext modification.
    
    :param plaintext_bytes: Raw binary content of the file
    :param key: 256-bit (32 bytes) encryption key (defaults to Config.MASTER_ENCRYPTION_KEY)
    :param associated_data: Optional authenticated metadata (AAD) bound to the ciphertext
    :return: tuple of (ciphertext_with_tag: bytes, nonce: bytes, sha256_hash: str)
    """
    if key is None:
        key = Config.MASTER_ENCRYPTION_KEY
    
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")
    
    # 1. Calculate original file SHA-256 hash for end-to-end integrity tracking
    sha256_hash = calculate_sha256(plaintext_bytes)
    
    # 2. Generate a secure random 96-bit nonce
    nonce = generate_nonce(12)
    
    # 3. Instantiate AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # 4. Encrypt plaintext (AESGCM encrypt automatically appends the 128-bit authentication tag)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
    
    return ciphertext, nonce, sha256_hash

def decrypt_file_data(ciphertext_bytes: bytes, nonce: bytes, expected_sha256: str = None, key: bytes = None, associated_data: bytes = None) -> tuple[bytes, bool]:
    """
    Decrypt file data using AES-256-GCM and verify integrity.
    
    If the ciphertext or authentication tag has been tampered with, AESGCM.decrypt
    will raise an InvalidTag exception.
    
    :param ciphertext_bytes: Encrypted payload (including GCM tag)
    :param nonce: The 12-byte nonce used during encryption
    :param expected_sha256: (Optional) SHA-256 hash to verify against decrypted plaintext
    :param key: 256-bit (32 bytes) encryption key
    :param associated_data: Optional authenticated metadata matching encryption
    :return: tuple of (decrypted_bytes: bytes, integrity_verified: bool)
    """
    if key is None:
        key = Config.MASTER_ENCRYPTION_KEY
        
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")
    
    aesgcm = AESGCM(key)
    
    # Decrypt and authenticate. Raises InvalidTag if ciphertext is tampered.
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_bytes, associated_data)
    
    # Verify SHA-256 integrity if hash is provided
    integrity_verified = True
    if expected_sha256:
        integrity_verified = verify_sha256_integrity(decrypted_bytes, expected_sha256)
        if not integrity_verified:
            raise ValueError("File integrity check failed: SHA-256 mismatch after decryption!")
            
    return decrypted_bytes, integrity_verified

def generate_share_token() -> str:
    """
    Generate a high-entropy URL-safe random token for expiring share links.
    """
    return secrets.token_urlsafe(32)
