# India_Method

**Overview:**

The India Method Cipher is a secure encryption algorithm based on ChaCha20 for encryption and HMAC-SHA256 for integrity verification. It ensures confidentiality, integrity, and authenticity of data.

**Features:**

Uses ChaCha20 stream cipher for high-speed encryption
HMAC-SHA256 for message integrity verification
Secure key derivation using HKDF
Supports file encryption and decryption
Implements key rotation for enhanced security

**Installation**

Ensure you have Python installed along with the required dependencies: pip install pycryptodome

**Usage:**

**How to Encrypt and Decrypt Data?**

import os
from india_method_cipher import IndiaMethodCipher

key = os.urandom(32)  # Generate a secure 256-bit key
nonce = os.urandom(16)  # Generate a unique 128-bit nonce
cipher = IndiaMethodCipher(key)

plaintext = b"Confidential Data"
encrypted_data = cipher.encrypt(plaintext, nonce)
decrypted_data = cipher.decrypt(encrypted_data)
assert decrypted_data == plaintext
print("Encryption and Decryption successful!")


**How to Encrypt and Decrypt Files?**

cipher.encrypt_file("input.txt", "encrypted_output.txt")
cipher.decrypt_file("encrypted_output.txt", "decrypted_output.txt")


**Key Rotation:**

new_key = os.urandom(32)
cipher.rotate_key(new_key)

**Security Considerations:**

Always use a securely generated key (256 bits)
Do not reuse nonces for the same key
Ensure HMAC verification is successful before decrypting

**License:**

This project is licensed under the MIT License.
