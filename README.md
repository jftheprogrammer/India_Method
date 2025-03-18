Enhanced India Method Cipher
Overview

The Enhanced India Method Cipher is an advanced cryptographic implementation designed for secure data encryption and decryption. This project, developed as part of a Master's dissertation, now incorporates Contextual Entropy Injection to enhance security by adapting encryption based on data patterns and metadata. It provides a robust, flexible, and secure solution for cryptographic research and application.
Features
Cryptographic Capabilities

    Multiple Cipher Support: Implements ChaCha20 and AES-GCM encryption algorithms.
    Contextual Entropy Injection: Adapts encryption keys and transformations based on data entropy characteristics and optional metadata.
    Advanced Key Derivation: Uses scrypt and HKDF for secure key generation, enhanced with contextual entropy.
    Memory-Efficient File Encryption: Supports streaming encryption/decryption for large files.

Security Mechanisms

    Constant-Time Operations: Mitigates side-channel attacks with constant-time padding and comparisons.
    Integrity Checks: Ensures data integrity using HMAC-SHA256.
    Flexible Key Rotation: Supports fixed-interval and time-based key rotation policies.
    Adaptive Transformations: Applies data-aware transformations (XOR, rotate, substitute) before encryption.

Project Structure
text
india-method-cipher/
├── indiaMethodCipher.py   # Main cipher implementation with Contextual Entropy Injection
├── unitTest.py            # Unit tests for the cipher
├── integrationTest.py     # Performance and integration tests
└── requirements.txt       # Python dependencies
Prerequisites

    Python 3.8 or higher
    Required libraries:
        pycryptodome (for ChaCha20, AES-GCM, HMAC, etc.)
        cryptography (for additional cryptographic primitives)
        numpy (for entropy analysis in Contextual Entropy Injection)

Installation

    Clone the repository:

bash
git clone https://github.com/jftheprogrammer/india-method-cipher.git
cd india-method-cipher

    Install dependencies:

bash
pip install -r requirements.txt

Or manually:
bash
pip install pycryptodome cryptography numpy
Usage Examples
Basic Encryption
python
from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType

# Initialize cipher
key = os.urandom(32)
cipher = EnhancedIndiaMethodCipher(
    key,
    cipher_type=CipherType.CHACHA20,
    key_rotation_policy=None
)

# Encrypt data with metadata
plaintext = b"Confidential Information"
metadata = {"author": "Joshua", "date": "2025-03-17"}
encrypted_data = cipher.encrypt(plaintext, metadata=metadata)
decrypted_data = cipher.decrypt(encrypted_data, metadata=metadata)
print(f"Decrypted: {decrypted_data}")
File Encryption
python
# Encrypt a file
metadata = {"author": "Joshua", "date": "2025-03-17"}
cipher.encrypt_file("input.txt", "encrypted.bin", metadata=metadata)
cipher.decrypt_file("encrypted.bin", "decrypted.txt", metadata=metadata)

Note: The same metadata used for encryption must be provided for decryption due to the contextual entropy injection. In a production system, consider securely storing transformation details with the encrypted data.
Running Tests
Unit Tests

Run the unit tests to verify the cipher's functionality:
bash
python -m unittest unitTest.py

This will execute tests for basic encryption/decryption, integrity checks, contextual encryption, and file operations.
Integration and Performance Tests

Run the integration and performance tests to evaluate the cipher's behavior with different scenarios and measure performance:
bash
python integrationTest.py

This generates a crypto_performance.log file with detailed results.
Performance Benchmarks

The integrationTest.py script includes performance benchmarking for:

    Different data sizes (1 KB, 1 MB, 10 MB)
    Cipher types (ChaCha20, AES-GCM)
    Encryption and decryption scenarios

Results are logged to crypto_performance.log for analysis.
Key Rotation Policies

    FIXED_INTERVAL: Rotates the key after 1000 uses.
    TIME_BASED: Rotates the key every 24 hours.
    None: No automatic rotation (manual rotation supported).

Security Considerations

    Key Length: Uses 256-bit keys for robust security.
    Contextual Entropy: Enhances key derivation and transformations based on data patterns, increasing resistance to pattern-based attacks.
    Metadata Dependency: Decryption requires the same metadata used during encryption. Future improvements could embed transformation details in the ciphertext.
    Side-Channel Resistance: Implements constant-time operations to prevent timing attacks.

Dissertation Research Points

    Advanced Cryptographic Design: Integration of contextual entropy into traditional ciphers.
    Side-Channel Attack Mitigation: Use of constant-time operations and adaptive transformations.
    Performance Analysis: Benchmarking across different data sizes and cipher types.
    Multi-Algorithm Frameworks: Support for ChaCha20 and AES-GCM.
    Adaptive Key Management: Contextual key derivation and rotation strategies.

Potential Future Improvements

    Embedded Transformation Data: Store transformation details securely in the ciphertext to eliminate metadata dependency.
    Post-Quantum Cryptography: Adapt the cipher for quantum-resistant algorithms.
    Hardware Acceleration: Integrate with Hardware Security Modules (HSM) for improved performance and security.
    Extended Authentication: Add support for authenticated encryption beyond HMAC.

License

MIT License
Author

Joshua L. Fernandez

Master's Dissertation Project
References

    NIST Cryptographic Standards
    Modern Cryptography Principles (e.g., Schneier, Ferguson)
    Side-Channel Attack Mitigation Techniques
