# India Method Encryption Algorithm

## Overview
India Method is a real-time encryption algorithm designed to provide secure and efficient encryption for data storage and transmission. Using AES encryption in CBC mode with SHA-256 key hashing, this method ensures confidentiality while maintaining high-speed processing.

## Features
- **Real-time encryption & decryption** – Fast and efficient processing.
- **Strong security** – Uses AES-256 encryption with CBC mode.
- **Lightweight** – Minimal computational overhead.
- **Flexible** – Can be integrated into various systems.
- **File Support** – Encrypt and decrypt files seamlessly.

## Installation
Clone the repository:
```bash
git clone https://github.com/your-username/india-method.git
cd india-method
```
Install dependencies:
```bash
pip install pycryptodome
```

## Usage

### Encrypting a Text String
```python
from india_method import IndiaMethod

key = "your-secret-key"
india = IndiaMethod(key)

plaintext = "Hello, World!"
encrypted = india.encrypt(plaintext)
print("Encrypted:", encrypted)
```

### Decrypting a Text String
```python
decrypted = india.decrypt(encrypted)
print("Decrypted:", decrypted)
```

### Encrypting and Saving to a File
```python
with open("encrypted.txt", "w") as f:
    f.write(encrypted)
```

### Reading and Decrypting from a File
```python
with open("encrypted.txt", "r") as f:
    loaded_encrypted = f.read()

decrypted_from_file = india.decrypt(loaded_encrypted)
print("Decrypted from file:", decrypted_from_file)
```

## License
This project is licensed under the **MIT License**. You are free to use, modify, and distribute it under the terms of the license.

## Contact
👤 **Joshua L. Fernandez**  
📍 Laoag City, Ilocos Norte  
✉ [Your Email or GitHub Profile Link]  

Feel free to contribute and improve this encryption method! 🚀

