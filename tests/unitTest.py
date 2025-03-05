import os
import unittest
import logging
from typing import List, Dict, Any

from improved_india_method_cipher import EnhancedIndiaMethodCipher, CipherType, KeyRotationPolicy

class TestEnhancedIndiaMethodCipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up logging and initialize test parameters
        """
        # Configure detailed logging for tests
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        cls.logger = logging.getLogger(__name__)
        
        # Generate secure test parameters
        cls.key = os.urandom(32)
        cls.nonce = os.urandom(16)

    def setUp(self):
        """
        Initialize cipher for each test method
        """
        self.cipher = EnhancedIndiaMethodCipher(
            self.key, 
            cipher_type=CipherType.CHACHA20,
            key_rotation_policy=KeyRotationPolicy.FIXED_INTERVAL,
            log_level=logging.DEBUG
        )

    def test_basic_encryption_decryption(self):
        """
        Test basic encryption and decryption functionality
        """
        test_cases: List[bytes] = [
            b"Sensitive Information",
            b"Hello, World!",
            b"12345",
            b"" # Empty string
        ]

        for plaintext in test_cases:
            with self.subTest(plaintext=plaintext):
                encrypted_data = self.cipher.encrypt(plaintext)
                decrypted_data = self.cipher.decrypt(encrypted_data)
                self.assertEqual(decrypted_data, plaintext)

    def test_integrity_check(self):
        """
        Test data integrity and tampering detection
        """
        plaintext = b"Test Data for Integrity Check"
        encrypted_data = self.cipher.encrypt(plaintext)

        # Simulate data tampering
        tampered_data = list(encrypted_data)
        tampered_data[-1] ^= 0x01  # Flip last bit
        
        with self.assertRaises(ValueError, msg="Integrity check should fail for tampered data"):
            self.cipher.decrypt(bytes(tampered_data))

    def test_multiple_cipher_types(self):
        """
        Test encryption with different cipher types
        """
        cipher_types = [CipherType.CHACHA20, CipherType.AES_GCM]
        test_data = b"Multi-Cipher Test Data"

        for cipher_type in cipher_types:
            with self.subTest(cipher_type=cipher_type):
                test_cipher = EnhancedIndiaMethodCipher(
                    self.key, 
                    cipher_type=cipher_type
                )
                encrypted = test_cipher.encrypt(test_data)
                decrypted = test_cipher.decrypt(encrypted)
                self.assertEqual(decrypted, test_data)

    def test_key_rotation(self):
        """
        Test key rotation mechanism
        """
        original_key = self.cipher.key
        new_key = os.urandom(32)
        
        self.cipher.rotate_key(new_key)
        
        # Verify key has been rotated
        self.assertNotEqual(original_key, self.cipher.key)
        self.assertEqual(len(self.cipher.key), 32)

    def test_file_encryption_decryption(self):
        """
        Comprehensive file encryption and decryption test
        """
        # Prepare test scenarios
        test_scenarios: List[Dict[str, Any]] = [
            {
                "content": b"Small file content",
                "filename": "small_test.txt"
            },
            {
                "content": os.urandom(1024 * 1024),  # 1MB random data
                "filename": "large_test.bin"
            }
        ]

        for scenario in test_scenarios:
            with self.subTest(filename=scenario['filename']):
                input_file = f"test_data/input_{scenario['filename']}"
                encrypted_file = f"test_data/encrypted_{scenario['filename']}"
                decrypted_file = f"test_data/decrypted_{scenario['filename']}"

                # Ensure test_data directory exists
                os.makedirs("test_data", exist_ok=True)

                # Write original content
                with open(input_file, "wb") as f:
                    f.write(scenario['content'])

                # Encrypt
                self.cipher.encrypt_file(input_file, encrypted_file)

                # Decrypt
                self.cipher.decrypt_file(encrypted_file, decrypted_file)

                # Verify content
                with open(decrypted_file, "rb") as f:
                    decrypted_content = f.read()
                
                self.assertEqual(decrypted_content, scenario['content'])

    def test_large_data_handling(self):
        """
        Test encryption and decryption of large data
        """
        # Generate large random data
        large_data = os.urandom(10 * 1024 * 1024)  # 10MB
        
        encrypted_data = self.cipher.encrypt(large_data)
        decrypted_data = self.cipher.decrypt(encrypted_data)
        
        self.assertEqual(decrypted_data, large_data)

    def test_error_handling(self):
        """
        Test various error scenarios
        """
        # Invalid key length
        with self.assertRaises(ValueError):
            EnhancedIndiaMethodCipher(os.urandom(16))  # 16-byte key instead of 32

        # Invalid nonce
        with self.assertRaises(ValueError):
            self.cipher.encrypt(b"Test", nonce=os.urandom(8))  # 8-byte nonce instead of 16

if __name__ == "__main__":
    unittest.main()
