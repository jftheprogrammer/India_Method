# Enhanced India Method Cipher

## Overview
The Enhanced India Method Cipher is an advanced cryptographic implementation designed for secure data encryption and decryption. This project provides a robust, flexible, and secure encryption solution with multiple features to support advanced cryptographic research.

## Features

### Cryptographic Capabilities
- Multiple Cipher Support (ChaCha20, AES-GCM)
- Advanced Key Derivation using Scrypt
- Flexible Key Rotation Policies
- Memory-Efficient File Encryption
- Side-Channel Attack Mitigation

### Security Mechanisms
- Constant-time Padding
- Comprehensive Integrity Checks
- Detailed Logging
- Adaptive Key Management

## Project Structure
```
india-method-cipher/
│
├── src/
│   └── IndiaMethodCipher.py        # Main cryptographic implementation
│
├── tests/
│   ├── unitTest.py                 # Comprehensive unit tests
│   └── integrationTest.py          # Performance and integration tests
│
├── README.md                       # Project documentation
└── requirements.txt                # Python dependencies
```

## Prerequisites
- Python 3.8+
- PyCryptodome Library
- unittest module

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/india-method-cipher.git
cd india-method-cipher
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage Examples

### Basic Encryption
```python
from IndiaMethodCipher import EnhancedIndiaMethodCipher, CipherType

# Initialize cipher
key = os.urandom(32)
cipher = EnhancedIndiaMethodCipher(
    key, 
    cipher_type=CipherType.CHACHA20
)

# Encrypt data
plaintext = b"Confidential Information"
encrypted_data = cipher.encrypt(plaintext)
decrypted_data = cipher.decrypt(encrypted_data)
```

### File Encryption
```python
# Encrypt entire file
cipher.encrypt_file("input.txt", "encrypted.bin")
cipher.decrypt_file("encrypted.bin", "decrypted.txt")
```

## Running Tests

### Unit Tests
```bash
python -m unittest tests/unitTest.py
```

### Integration Tests
```bash
python tests/integrationTest.py
```

## Performance Benchmarks
The `integrationTest.py` script includes comprehensive performance benchmarking across different:
- Cipher Types
- Data Sizes
- Encryption Scenarios

## Key Rotation Policies
- `FIXED_INTERVAL`: Rotate key after fixed number of uses
- `TIME_BASED`: Rotate key periodically
- `USAGE_BASED`: Custom rotation strategy

## Security Considerations
- 256-bit key length
- Adaptive key derivation
- Side-channel attack resistance
- Constant-time comparisons

## Logging
Comprehensive logging is implemented with configurable log levels:
- DEBUG: Detailed debugging information
- INFO: General operational events
- ERROR: Error tracking

## Dissertation Research Points
1. Advanced Cryptographic Design
2. Side-Channel Attack Mitigation
3. Performance Analysis
4. Multi-Algorithm Cryptographic Frameworks
5. Adaptive Key Management Strategies

## Potential Future Improvements
- Hardware Security Module (HSM) Integration
- Post-Quantum Cryptography Adaptation
- Extended Authentication Mechanisms
- Enhanced Key Management

## License
[Specify your license, e.g., MIT, Apache 2.0]

## Author
[Your Name]
Master's Dissertation Project

## References
- NIST Cryptographic Standards
- Modern Cryptography Principles
- Side-Channel Attack Mitigation Techniques
