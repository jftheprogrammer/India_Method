import os
from Crypto.Cipher import ChaCha20
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF

class IndiaMethodCipher:
    """
    India Method Cipher: A ChaCha20-based encryption algorithm with HMAC integrity verification.
    Provides secure encryption and decryption of data and files.
    """
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        self.key = key
        self.enc_key, self.hmac_key = self._derive_keys(key)

    def _derive_keys(self, master_key: bytes) -> tuple[bytes, bytes]:
        """Derives separate encryption and HMAC keys from the master key."""
        enc_key = HKDF(master_key, 32, b"encryption", SHA256)
        hmac_key = HKDF(master_key, 32, b"hmac", SHA256)
        return enc_key, hmac_key

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        """Encrypts data using ChaCha20 and appends HMAC for integrity verification."""
        if len(nonce) != 16:
            raise ValueError("Nonce must be 128 bits (16 bytes)")
        
        cipher = ChaCha20.new(key=self.enc_key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        
        # Generate HMAC for integrity
        hmac = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
        return nonce + ciphertext + hmac.digest()
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypts data and verifies integrity using HMAC."""
        if len(encrypted_data) < 48:
            raise ValueError("Invalid encrypted data format")
        
        nonce = encrypted_data[:16]
        hmac_received = encrypted_data[-32:]
        ciphertext = encrypted_data[16:-32]
        
        # Verify HMAC integrity
        hmac = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
        if hmac.digest() != hmac_received:
            raise ValueError("Integrity check failed: Data may be tampered")
        
        cipher = ChaCha20.new(key=self.enc_key, nonce=nonce)
        return cipher.decrypt(ciphertext)
    
    def encrypt_file(self, input_file: str, output_file: str):
        """Encrypts a file and saves the output."""
        nonce = os.urandom(16)
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        encrypted_data = self.encrypt(plaintext, nonce)
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
    
    def decrypt_file(self, input_file: str, output_file: str):
        """Decrypts a file and saves the output."""
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        plaintext = self.decrypt(encrypted_data)
        with open(output_file, 'wb') as f:
            f.write(plaintext)
    
    def rotate_key(self, new_key: bytes):
        """Rotates encryption key to a new 256-bit key."""
        if len(new_key) != 32:
            raise ValueError("New key must be 256 bits (32 bytes)")
        self.key = new_key
        self.enc_key, self.hmac_key = self._derive_keys(new_key)
    
# Example Usage
if __name__ == "__main__":
    key = os.urandom(32)  # Generate a secure 256-bit key
    nonce = os.urandom(16)  # Generate a unique 128-bit nonce
    cipher = IndiaMethodCipher(key)

    plaintext = b"Confidential Data"
    encrypted_data = cipher.encrypt(plaintext, nonce)
    decrypted_data = cipher.decrypt(encrypted_data)

    assert decrypted_data == plaintext
    print("Encryption and Decryption successful!")

    # Example File Encryption
    test_file = "test.txt"
    with open(test_file, "wb") as f:
        f.write(plaintext)
    cipher.encrypt_file("test.txt", "encrypted_test.txt")
    cipher.decrypt_file("encrypted_test.txt", "decrypted_test.txt")
    with open("decrypted_test.txt", "rb") as f:
        assert f.read() == plaintext
    print("File Encryption and Decryption successful!")
