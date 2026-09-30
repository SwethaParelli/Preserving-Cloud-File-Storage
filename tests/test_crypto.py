import unittest
import os
from crypto_utils import (
    hash_password,
    check_password,
    calculate_sha256,
    verify_sha256_integrity,
    encrypt_file_data,
    decrypt_file_data,
    generate_share_token
)

class TestCryptoUtils(unittest.TestCase):
    def test_password_hashing(self):
        password = "SecurePassword123!"
        hashed = hash_password(password)
        
        self.assertNotEqual(password, hashed)
        self.assertTrue(check_password(password, hashed))
        self.assertFalse(check_password("WrongPassword", hashed))

    def test_sha256_hash_and_integrity(self):
        sample_data = b"Confidential financial statement data for B.Tech project."
        sha_hash = calculate_sha256(sample_data)
        self.assertEqual(len(sha_hash), 64)
        self.assertTrue(verify_sha256_integrity(sample_data, sha_hash))
        self.assertFalse(verify_sha256_integrity(b"Tampered data", sha_hash))

    def test_aes_256_gcm_encrypt_decrypt(self):
        original_content = b"Top secret document with highly sensitive credentials."
        ciphertext, nonce, sha_hash = encrypt_file_data(original_content)
        
        # Ensure ciphertext is different from original
        self.assertNotEqual(ciphertext, original_content)
        self.assertEqual(len(nonce), 12) # 96-bit nonce
        
        # Decrypt and verify
        decrypted_content, integrity_valid = decrypt_file_data(
            ciphertext_bytes=ciphertext,
            nonce=nonce,
            expected_sha256=sha_hash
        )
        
        self.assertEqual(decrypted_content, original_content)
        self.assertTrue(integrity_valid)

    def test_aes_256_gcm_tamper_resistance(self):
        original_content = b"Integrity protected payload."
        ciphertext, nonce, sha_hash = encrypt_file_data(original_content)
        
        # Tamper with the ciphertext (flip a byte)
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        tampered_ciphertext = bytes(tampered_ciphertext)
        
        # AES-GCM must reject tampered ciphertext
        with self.assertRaises(Exception):
            decrypt_file_data(tampered_ciphertext, nonce, sha_hash)

    def test_share_token_generation(self):
        token1 = generate_share_token()
        token2 = generate_share_token()
        self.assertNotEqual(token1, token2)
        self.assertGreater(len(token1), 30)

if __name__ == "__main__":
    unittest.main()
