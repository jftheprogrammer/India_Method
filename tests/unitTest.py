import os
import unittest
import logging
from typing import List, Dict, Any

from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType, KeyRotationPolicy

class TestEnhancedIndiaMethodCipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        cls.logger = logging.getLogger(__name__)
        cls.key = os.urandom(32)
        cls.nonce = os.urandom(16)

    def setUp(self):
        self.cipher = EnhancedIndiaMethodCipher(
            self.key,
            cipher_type=CipherType.CHACHA20,
            key_rotation_policy=KeyRotationPolicy.FIXED_INTERVAL,
            log_level=logging.DEBUG
        )

    def test_basic_encryption_decryption(self):
        test_cases: List[bytes] = [
            b"Sensitive Information",
            b"Hello, World!",
            b"12345",
            b""
        ]
        metadata = {"author": "Test", "date": "2025-03-17"}
        for plaintext in test_cases:
            with self.subTest(plaintext=plaintext):
                encrypted_data = self.cipher.encrypt(plaintext, metadata=metadata)
                decrypted_data = self.cipher.decrypt(encrypted_data, metadata=metadata)
                self.assertEqual(decrypted_data, plaintext)

    def test_integrity_check(self):
        plaintext = b"Test Data for Integrity Check"
        metadata = {"author": "Test", "date": "2025-03-17"}
        encrypted_data = self.cipher.encrypt(plaintext, metadata=metadata)
        tampered_data = list(encrypted_data)
        tampered_data[-1] ^= 0x01
        with self.assertRaises(ValueError):
            self.cipher.decrypt(bytes(tampered_data), metadata=metadata)

    def test_contextual_encryption(self):
        metadata = {"author": "Joshua", "date": "2025-03-17"}
        plaintext = b"Contextual Test Data"
        encrypted_data = self.cipher.encrypt(plaintext, metadata=metadata)
        decrypted_data = self.cipher.decrypt(encrypted_data, metadata=metadata)
        self.assertEqual(decrypted_data, plaintext)
        with self.assertRaises(Exception):
            self.cipher.decrypt(encrypted_data, metadata={"author": "Different"})

    def test_file_encryption_decryption(self):
        test_scenarios: List[Dict[str, Any]] = [
            {"content": b"Small file content", "filename": "small_test.txt"},
            {"content": os.urandom(1024 * 1024), "filename": "large_test.bin"}
        ]
        metadata = {"author": "Test", "date": "2025-03-17"}
        for scenario in test_scenarios:
            with self.subTest(filename=scenario['filename']):
                os.makedirs("test_data", exist_ok=True)
                input_file = f"test_data/input_{scenario['filename']}"
                encrypted_file = f"test_data/encrypted_{scenario['filename']}"
                decrypted_file = f"test_data/decrypted_{scenario['filename']}"
                with open(input_file, "wb") as f:
                    f.write(scenario['content'])
                self.cipher.encrypt_file(input_file, encrypted_file, metadata=metadata)
                self.cipher.decrypt_file(encrypted_file, decrypted_file, metadata=metadata)
                with open(decrypted_file, "rb") as f:
                    decrypted_content = f.read()
                self.assertEqual(decrypted_content, scenario['content'])

if __name__ == "__main__":
    unittest.main()
