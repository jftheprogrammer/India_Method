import os
import unittest
from india_method_cipher import IndiaMethodCipher

class TestIndiaMethodCipher(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize the cipher with a random key before tests"""
        cls.key = os.urandom(32)
        cls.nonce = os.urandom(16)
        cls.cipher = IndiaMethodCipher(cls.key)

    def test_encryption_decryption(self):
        """Test if encryption and decryption return the original plaintext"""
        plaintext = b"Sensitive Information"
        encrypted_data = self.cipher.encrypt(plaintext, self.nonce)
        decrypted_data = self.cipher.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, plaintext)

    def test_integrity_check(self):
        """Test if tampered data fails the integrity check"""
        plaintext = b"Test Data"
        encrypted_data = self.cipher.encrypt(plaintext, self.nonce)

        # Modify encrypted data (simulating an attack)
        tampered_data = encrypted_data[:-1] + bytes([encrypted_data[-1] ^ 0x01])

        with self.assertRaises(ValueError):
            self.cipher.decrypt(tampered_data)

    def test_file_encryption_decryption(self):
        """Test if file encryption and decryption work correctly"""
        test_file = "test.txt"
        encrypted_file = "test_encrypted.bin"
        decrypted_file = "test_decrypted.txt"

        with open(test_file, "wb") as f:
            f.write(b"File Encryption Test")

        self.cipher.encrypt_file(test_file, encrypted_file)
        self.cipher.decrypt_file(encrypted_file, decrypted_file)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(decrypted_content, b"File Encryption Test")

if __name__ == "__main__":
    unittest.main()
