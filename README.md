Enhanced India Method Cipher

A highly configurable, secure, and modern cryptographic system designed for advanced encryption and decryption, integrating classical and post-quantum cryptography with adaptive security features. This project, developed as part of a Master's dissertation, offers a robust framework for protecting sensitive data with cutting-edge techniques.
Features

    Multiple Cipher Types: Supports ChaCha20, AES-GCM, and Kyber (post-quantum KEM).
    Post-Quantum Cryptography: Integrates CRYSTALS-Kyber for quantum-resistant encryption (KEM only; signatures like Dilithium are planned for future work).
    HSM Integration: Mock Hardware Security Module (HSM) support with a placeholder for real PKCS#11 integration.
    Adaptive Security: Dynamically adjusts security levels (Low, Medium, High, Ultra) based on data size and sensitivity.
    Enhanced Contextual Entropy: Incorporates Rényi entropy, min-entropy, compression ratio, and environmental context (e.g., timestamp) into key derivation for data-aware security.
    Compression: Optional zlib compression before encryption to reduce ciphertext size and enhance entropy.
    Parallel Processing: Multi-threaded encryption/decryption for large files using ThreadPoolExecutor.
    Statistical Cryptanalysis: Visualizes the avalanche effect to assess cryptographic strength (NIST suite preparatory).
    Formal Verification: Includes a Z3-based proof of correctness (simplified model) with preparatory TLA+ specifications in comments.
    Key Rotation: Configurable policies (fixed interval, usage-based, time-based) for key management.

Project Structure
text
Enhanced-India-Method-Cipher/
├── indiaMethodCipher.py    # Core cipher implementation
├── unitTest.py            # Unit tests for individual components
├── integrationTest.py     # Integration and performance tests
├── requirements.txt       # Dependencies
└── README.md             # This file
Prerequisites

    Python: 3.8 or higher
    Dependencies: Listed in requirements.txt

Installation

    Clone the Repository:
    bash

git clone https://github.com/yourusername/Enhanced-India-Method-Cipher.git
cd Enhanced-India-Method-Cipher
Set Up a Virtual Environment (optional but recommended):
bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install Dependencies:
bash

    pip install -r requirements.txt

Usage
Basic Encryption/Decryption
python
from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType, SecurityLevel
import os

# Generate a 32-byte key
key = os.urandom(32)

# Initialize the cipher
cipher = EnhancedIndiaMethodCipher(
    key,
    cipher_type=CipherType.CHACHA20,
    security_level=SecurityLevel.MEDIUM,
    adaptive_security=True
)

# Encrypt text
plaintext = b"Sensitive Data"
encrypted = cipher.encrypt(plaintext, compress=True)

# Decrypt text
decrypted = cipher.decrypt(encrypted)
print(f"Original: {plaintext}, Decrypted: {decrypted}")
File Encryption/Decryption
python
# Encrypt a file
cipher.encrypt_file("input.txt", "encrypted.bin", compress=True, chunk_size=1024*1024)

# Decrypt a file
cipher.decrypt_file("encrypted.bin", "output.txt")
Formal Verification
python
# Verify cipher correctness
is_correct = cipher.verify_correctness()
print(f"Cipher Verified: {is_correct}")
Avalanche Effect Visualization
python
# Visualize the avalanche effect
cipher.visualize_avalanche_effect(b"Test Data", num_bits=10, output_file="avalanche.png")
Security Levels

The cipher supports four security levels with corresponding parameters:

    Low: 16-byte key, 1 entropy round, 1 transform round, SHA256
    Medium: 32-byte key, 3 entropy rounds, 2 transform rounds, SHA256
    High: 32-byte key, 5 entropy rounds, 3 transform rounds, SHA384
    Ultra: 32-byte key, 7 entropy rounds, 5 transform rounds, SHA512, post-quantum enabled

Testing
Unit Tests

Run unit tests to validate individual components:
bash
python -m unittest unitTest.py

Covers:

    Basic encryption/decryption
    Compression
    Parallel file processing
    Formal verification
    Integrity checks
    Post-quantum and HSM functionality
    Adaptive security
    Edge cases (e.g., invalid keys, corrupted data)

Integration Tests

Run integration tests for system-wide validation and performance:
bash
python integrationTest.py

Includes:

    Comprehensive scenario testing (e.g., small compressed, large adaptive)
    Performance benchmarking (encryption/decryption times)
    Stress testing (50MB file)

Dependencies

    pycryptodome: Cryptographic primitives
    cryptography: Additional cipher support
    numpy: Entropy calculations
    oqspy: Post-quantum Kyber implementation
    matplotlib: Avalanche effect visualization
    z3-solver: Formal verification

Install via:
bash
pip install pycryptodome cryptography numpy oqspy matplotlib z3-solver
Limitations

    HSM: Currently uses a mock implementation; real PKCS#11 requires additional setup.
    Post-Quantum: Only Kyber KEM is implemented; signatures (e.g., Dilithium) are not included.
    NIST Suite: Preparatory only; full statistical testing requires an external library.
    Formal Verification: Simplified Z3 model; full TLA+ implementation needs separate tools.

Future Work

    Integrate real HSM support with PKCS#11.
    Add post-quantum signatures (e.g., Dilithium).
    Implement the full NIST Statistical Test Suite.
    Enhance formal verification with executable TLA+ or deeper Z3 models.
    Develop a CLI or GUI for easier interaction.

Contributing

Contributions are welcome! Please:

    Fork the repository.
    Create a feature branch (git checkout -b feature/your-feature).
    Commit changes (git commit -m "Add your feature").
    Push to the branch (git push origin feature/your-feature).
    Open a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

    Built as part of a Master's dissertation at [Your University].
    Inspired by advancements in post-quantum cryptography and adaptive security.

This README provides a clear overview of your project, its capabilities, and how to use it, without referencing the real-life applications we discussed. It’s structured to be professional and informative, suitable for academic or public sharing. Let me know if you’d like to adjust anything (e.g., add a specific license, include your name/university, or tweak the tone)!
