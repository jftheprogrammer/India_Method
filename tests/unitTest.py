import os
import unittest
import logging
import shutil
from typing import List, Dict, Any
from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType, KeyRotationPolicy, SecurityLevel

class TestEnhancedIndiaMethodCipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        cls.logger = logging.getLogger(__name__)
        cls.key = os.urandom(32)
        cls.nonce = os.urandom(16)
        cls.test_dir = "test_data"
        os.makedirs(cls.test_dir, exist_ok=True)

    def setUp(self):
        self.cipher = EnhancedIndiaMethodCipher(
            self.key,
            cipher_type=CipherType.CHACHA20,
            key_rotation_policy=KeyRotationPolicy.FIXED_INTERVAL,
            log_level=logging.DEBUG,
            security_level=SecurityLevel.MEDIUM
        )

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir, exist_ok=True)

    # Basic Encryption/Decryption Tests
    def test_basic_encryption_decryption(self):
        test_cases: List[bytes] = [
            b"Sensitive Information",
            b"Hello, World!",
            b"12345",
            b"",  # Empty input
            b"\x00\xFF\xAA" * 100  # Binary data
        ]
        for plaintext in test_cases:
            with self.subTest(plaintext=plaintext):
                encrypted_data = self.cipher.encrypt(plaintext)
                decrypted_data = self.cipher.decrypt(encrypted_data)
                self.assertEqual(decrypted_data, plaintext)

    # Compression Tests
    def test_compression_encryption(self):
        test_cases: List[bytes] = [
            b"Compressible Data " * 100,  # Highly compressible
            b"Random" + os.urandom(100),  # Partially compressible
            os.urandom(1024)  # Incompressible
        ]
        for plaintext in test_cases:
            with self.subTest(plaintext=plaintext):
                encrypted = self.cipher.encrypt(plaintext, compress=True)
                decrypted = self.cipher.decrypt(encrypted)
                self.assertEqual(decrypted, plaintext)
                if b"Compressible" in plaintext:
                    self.assertLess(len(encrypted), len(plaintext) + 100)

    def test_compression_disabled(self):
        plaintext = b"Compressible Data " * 100
        encrypted = self.cipher.encrypt(plaintext, compress=False)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
        self.assertGreater(len(encrypted), len(plaintext))  # No compression overhead

    # Parallel Processing Tests
    def test_parallel_file_encryption_small(self):
        input_file = f"{self.test_dir}/small_input.bin"
        encrypted_file = f"{self.test_dir}/small_encrypted.bin"
        decrypted_file = f"{self.test_dir}/small_decrypted.bin"
        data = b"Small File"
        with open(input_file, "wb") as f:
            f.write(data)
        self.cipher.encrypt_file(input_file, encrypted_file, chunk_size=1024)
        self.cipher.decrypt_file(encrypted_file, decrypted_file)
        with open(decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, data)

    def test_parallel_file_encryption_large(self):
        input_file = f"{self.test_dir}/large_input.bin"
        encrypted_file = f"{self.test_dir}/large_encrypted.bin"
        decrypted_file = f"{self.test_dir}/large_decrypted.bin"
        data = os.urandom(5 * 1024 * 1024)  # 5MB
        with open(input_file, "wb") as f:
            f.write(data)
        self.cipher.encrypt_file(input_file, encrypted_file, chunk_size=1024*1024)
        self.cipher.decrypt_file(encrypted_file, decrypted_file)
        with open(decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, data)

    # Formal Verification Test
    def test_formal_verification(self):
        self.assertTrue(self.cipher.verify_correctness(), "Formal verification failed")

    # Integrity and Security Tests
    def test_integrity_check(self):
        plaintext = b"Test Data for Integrity Check"
        encrypted_data = self.cipher.encrypt(plaintext)
        tampered_data = list(encrypted_data)
        tampered_data[-1] ^= 0x01  # Tamper HMAC
        with self.assertRaises(ValueError):
            self.cipher.decrypt(bytes(tampered_data))

    def test_header_tampering(self):
        plaintext = b"Test Header Integrity"
        encrypted_data = self.cipher.encrypt(plaintext)
        tampered_data = list(encrypted_data)
        tampered_data[16] ^= 0x01  # Tamper header ciphertext
        with self.assertRaises(Exception):  # AES-GCM raises ValueError or DecryptionError
            self.cipher.decrypt(bytes(tampered_data))

    # Post-Quantum Tests
    def test_post_quantum_encryption(self):
        cipher = EnhancedIndiaMethodCipher(self.key, cipher_type=CipherType.KYBER, pq_enabled=True)
        plaintext = b"Quantum Test"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    # HSM Tests
    def test_hsm_encryption(self):
        cipher = EnhancedIndiaMethodCipher(self.key, hsm_enabled=True, hsm_config={"type": "softHSM"})
        plaintext = b"HSM Test"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    # Adaptive Security Tests
    def test_adaptive_security_low(self):
        cipher = EnhancedIndiaMethodCipher(self.key, adaptive_security=True)
        plaintext = b"Small"  # Small data
        cipher.adjust_security_level(data=plaintext)
        self.assertEqual(cipher.security_level, SecurityLevel.LOW)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_adaptive_security_high(self):
        cipher = EnhancedIndiaMethodCipher(self.key, adaptive_security=True)
        plaintext = os.urandom(1024 * 1024)  # 1MB
        cipher.adjust_security_level(data=plaintext)
        self.assertGreaterEqual(cipher.security_level, SecurityLevel.HIGH)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    # Enhanced Entropy Tests
    def test_enhanced_entropy(self):
        plaintext = b"Enhanced Entropy Test" * 10
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    # Avalanche Effect Test
    def test_avalanche_effect(self):
        plaintext = b"Test Avalanche"
        self.cipher.visualize_avalanche_effect(plaintext, num_bits=5)  # Visual, no assertion

    # Edge Cases
    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            EnhancedIndiaMethodCipher(b"short", security_level=SecurityLevel.MEDIUM)

    def test_corrupted_file(self):
        input_file = f"{self.test_dir}/corrupt_input.bin"
        encrypted_file = f"{self.test_dir}/corrupt_encrypted.bin"
        data = b"Valid Data"
        with open(input_file, "wb") as f:
            f.write(data)
        self.cipher.encrypt_file(input_file, encrypted_file)
        with open(encrypted_file, "r+b") as f:
            f.seek(20)
            f.write(b"\xFF")  # Corrupt header
        with self.assertRaises(Exception):
            self.cipher.decrypt_file(encrypted_file, f"{self.test_dir}/corrupt_decrypted.bin")

if __name__ == "__main__":
    unittest.main()
