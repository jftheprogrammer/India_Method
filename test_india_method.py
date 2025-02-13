import os
from india_method_cipher import IndiaMethodCipher

# Initialize cipher with a secure random key
key = os.urandom(32)
nonce = os.urandom(16)
cipher = IndiaMethodCipher(key)

# Define file paths
plaintext_file = "test_data/plaintext_sample.txt"
encrypted_file = "test_data/encrypted_sample.bin"
decrypted_file = "test_data/decrypted_sample.txt"

# Ensure test_data directory exists
os.makedirs("test_data", exist_ok=True)

# Step 1: Create a sample plaintext file
with open(plaintext_file, "wb") as f:
    f.write(b"This is a test message for encryption.")

# Step 2: Encrypt the file
cipher.encrypt_file(plaintext_file, encrypted_file)
print(f"File encrypted successfully: {encrypted_file}")

# Step 3: Decrypt the file
cipher.decrypt_file(encrypted_file, decrypted_file)
print(f"File decrypted successfully: {decrypted_file}")

# Step 4: Verify integrity
with open(plaintext_file, "rb") as f1, open(decrypted_file, "rb") as f2:
    assert f1.read() == f2.read(), "Error: Decrypted file does not match original!"

print("Test completed successfully: Encryption and Decryption verified!")
