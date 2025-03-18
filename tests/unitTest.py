import os
import unittest
import logging
from typing import List, Dict, Any
from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType, KeyRotationPolicy, SecurityLevel

class TestEnhancedIndiaMethodCipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        cls.logger = logging.getLogger(__name__)
        cls.key = os.urandom(32)
        cls.nonce = os.urandom(16)

    def setUp(self):
        self.cipher = EnhancedIndiaMethodCipher(
            self.key,
            cipher_type=CipherType.CHACHA20,
            key_rotation_policy=KeyRotationPolicy.FIXED_INTERVAL,
            log_level=logging.DEBUG,
            security_level=SecurityLevel.MEDIUM
        )

    def test_basic_encryption_decryption(self):
        test_cases: List[bytes] = [b"Sensitive Information", b"Hello, World!", b"12345", b""]
        for plaintext in test_cases:
            with self.subTest(plaintext=plaintext):
                encrypted_data = self.cipher.encrypt(plaintext)
                decrypted_data = self.cipher.decrypt(encrypted_data)
                self.assertEqual(decrypted_data, plaintext)

    def test_compression_encryption(self):
        plaintext = b"Compressible Data " * 100  # Repetitive for compression
        encrypted = self.cipher.encrypt(plaintext, compress=True)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
        self.assertLess(len(encrypted), len(plaintext) + 100)  # Compression reduces size

    def test_parallel_file_encryption(self):
        os.makedirs("test_data", exist_ok=True)
        input_file = "test_data/large_input.bin"
        encrypted_file = "test_data/large_encrypted.bin"
        decrypted_file = "test_data/large_decrypted.bin"
        data = os.urandom(5 * 1024 * 1024)  # 5MB
        with open(input_file, "wb") as f:
            f.write(data)
        self.cipher.encrypt_file(input_file, encrypted_file, chunk_size=1024*1024)
        self.cipher.decrypt_file(encrypted_file, decrypted_file)
        with open(decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, data)

    def test_formal_verification(self):
        self.assertTrue(self.cipher.verify_correctness(), "Formal verification failed")

    def test_integrity_check(self):
        plaintext = b"Test Data for Integrity Check"
        encrypted_data = self.cipher.encrypt(plaintext)
        tampered_data = list(encrypted_data)
        tampered_data[-1] ^= 0x01
        with self.assertRaises(ValueError):
            self.cipher.decrypt(bytes(tampered_data))

    def test_adaptive_security(self):
        cipher = EnhancedIndiaMethodCipher(self.key, adaptive_security=True)
        plaintext = os.urandom(1024 * 1024)  # 1MB
        cipher.adjust_security_level(data=plaintext)
        self.assertGreaterEqual(cipher.security_level, SecurityLevel.HIGH)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

if __name__ == "__main__":
    unittest.main()
