# Enhanced India Method Cipher

A robust, post-quantum-ready cryptographic system with hardware security module (HSM) support, advanced entropy analysis, and formal verification.

## Overview

This project implements an enhanced version of the India Method Cipher (`EnhancedIndiaMethodCipher`), a versatile encryption system featuring:

- **Symmetric Encryption**: Supports ChaCha20, AES-GCM, and Kyber (post-quantum KEM).
- **HSM Integration**: Real PKCS#11 support for hardware-accelerated cryptography.
- **Post-Quantum Signatures**: Dilithium signatures for quantum-resistant integrity.
- **NIST Statistical Tests**: Comprehensive randomness testing per NIST SP 800-22.
- **Formal Verification**: Z3 solver and executable TLA+ specifications for correctness.
- **Adaptive Security**: Dynamically adjusts security levels based on data sensitivity.
- **File Encryption**: Efficient parallel processing for large files.

The codebase includes unit tests (`unitTest.py`) and integration/performance tests (`integrationTest.py`) to ensure reliability and performance.

## Features

- **Cipher Types**: ChaCha20, AES-GCM, Kyber.
- **Security Levels**: Low, Medium, High, Ultra (with post-quantum enhancements).
- **Key Rotation**: Fixed interval, usage-based, or time-based policies.
- **Contextual Entropy**: Advanced data pattern analysis for key derivation.
- **Compression**: Optional zlib compression for encrypted data.
- **Visualization**: Avalanche effect analysis with Matplotlib.

## Requirements

### Dependencies
Install the required Python packages:
```bash
pip install pycryptodome cryptography numpy oqspy matplotlib z3-solver python-pkcs11 scipy
```

### Additional Setup

- **HSM**: Configure a PKCS#11-compatible HSM (e.g., SoftHSM2):
  - Install SoftHSM2: `sudo apt-get install softhsm2` (Ubuntu) or equivalent.
  - Initialize a token: `softhsm2-util --init-token --slot 0 --label "MyToken" --pin 1234 --so-pin 123456`.
  - Update `hsm_config` in code if using a different library path or PIN.
- **TLA+**: For formal verification:
  - Install TLA+ Toolbox or TLC: Download from TLA+ Tools.
  - Ensure `tlc` is in your PATH: `java -jar tlc.jar`.

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd <repository-directory>
```
2. Install dependencies (see above).
3. Configure HSM if using (`hsm_enabled=True`).

## Usage

### Basic Example
```python
from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType, SecurityLevel
import os

key = os.urandom(32)
cipher = EnhancedIndiaMethodCipher(
    key,
    cipher_type=CipherType.CHACHA20,
    security_level=SecurityLevel.ULTRA,
    hsm_enabled=True,
    hsm_config={"lib_path": "/usr/lib/softhsm/libsofthsm2.so", "pin": "1234"}
)

plaintext = b"Secret Message"
encrypted = cipher.encrypt(plaintext, compress=True)
decrypted = cipher.decrypt(encrypted)
print(f"Decrypted: {decrypted}")  # Output: b"Secret Message"

# Verify correctness
assert cipher.verify_correctness(), "Z3 verification failed"
assert cipher.verify_with_tla(), "TLA+ verification failed"
assert cipher.nist_suite.run_tests(encrypted), "NIST suite failed"
```

### File Encryption
```python
cipher.encrypt_file("input.txt", "encrypted.bin", metadata={"type": "sensitive"}, compress=True)
cipher.decrypt_file("encrypted.bin", "output.txt")
```

### Visualization
```python
cipher.visualize_avalanche_effect(b"Test Data", num_bits=10, output_file="avalanche.png")
```

## Testing

### Unit Tests

Run unit tests to verify individual components:
```bash
python -m unittest unitTest.py
```

- Covers encryption/decryption, HSM, Dilithium, NIST suite, formal verification, and edge cases.

### Integration Tests

Run integration and performance tests:
```bash
python integrationTest.py
```

- Includes comprehensive scenarios, performance benchmarks, and a stress test with a 50MB file.

## Project Structure

- `indiaMethodCipher.py`: Core cipher implementation.
- `unitTest.py`: Unit tests for individual functionalities.
- `integrationTest.py`: Integration, performance, and stress tests.

## Notes

- **HSM Configuration**: Adjust `hsm_config` in tests if your HSM setup differs (e.g., different `lib_path` or `pin`).
- **NIST Suite**: Requires at least 1M bits of data for reliable results (125KB+).
- **Performance**: HSM and Dilithium may increase latency; tune `chunk_size` for large files.
- **TLA+**: Simplified model; extend `verify_with_tla` for deeper analysis.

## Contributing

Feel free to submit issues or pull requests for enhancements, bug fixes, or additional test cases.

## License

This project is licensed under the MIT License. See LICENSE file for details.

Generated on March 19, 2025
