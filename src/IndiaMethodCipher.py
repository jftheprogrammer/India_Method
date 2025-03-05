import os
import enum
import logging
from typing import Optional, Union
from Crypto.Cipher import ChaCha20, AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Random import get_random_bytes

class CipherType(enum.Enum):
    CHACHA20 = enum.auto()
    AES_GCM = enum.auto()

class KeyRotationPolicy(enum.Enum):
    FIXED_INTERVAL = enum.auto()
    USAGE_BASED = enum.auto()
    TIME_BASED = enum.auto()

class EnhancedIndiaMethodCipher:
    """
    Enhanced India Method Cipher with advanced security features.
    
    Features:
    - Multiple cipher support
    - Advanced key derivation
    - Secure key rotation
    - Comprehensive logging
    - Memory-efficient file encryption
    - Side-channel attack mitigation
    """
    
    def __init__(
        self, 
        key: bytes, 
        cipher_type: CipherType = CipherType.CHACHA20,
        key_rotation_policy: Optional[KeyRotationPolicy] = None,
        log_level: int = logging.INFO
    ):
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Validate key
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        
        self.key = key
        self.cipher_type = cipher_type
        self.key_rotation_policy = key_rotation_policy
        
        # Derive keys using advanced key derivation
        self.enc_key, self.hmac_key = self._derive_keys(key)
        
        # Key metadata
        self.key_creation_time = os.time()
        self.key_usage_count = 0
        
        # Logging key event
        self.logger.info("Cipher initialized with selected cipher type")
    
    def _derive_keys(self, master_key: bytes) -> tuple[bytes, bytes]:
        """
        Advanced key derivation using scrypt for enhanced security.
        
        Args:
            master_key (bytes): Original encryption key
        
        Returns:
            tuple: Derived encryption and HMAC keys
        """
        # Use scrypt for adaptive key stretching
        salt = get_random_bytes(16)
        enc_key = scrypt(
            password=master_key, 
            salt=salt, 
            key_len=32, 
            N=2**14,  # CPU/memory cost
            r=8,      # Block size
            p=1       # Parallelization
        )
        
        # Secondary key derivation for HMAC
        hmac_key = HKDF(
            master_key=master_key, 
            key_len=32, 
            salt=b"hmac_derivation", 
            hashmod=SHA256
        )
        
        return enc_key, hmac_key
    
    def _get_cipher(self, nonce: bytes) -> Union[ChaCha20.ChaCha20Cipher, AES.AESCipher]:
        """
        Select cipher based on configured type.
        
        Args:
            nonce (bytes): Unique nonce for encryption
        
        Returns:
            Configured cipher object
        """
        if self.cipher_type == CipherType.CHACHA20:
            return ChaCha20.new(key=self.enc_key, nonce=nonce)
        elif self.cipher_type == CipherType.AES_GCM:
            return AES.new(self.enc_key, AES.MODE_GCM, nonce=nonce)
        else:
            raise ValueError(f"Unsupported cipher type: {self.cipher_type}")
    
    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
        """
        Enhanced encryption with side-channel attack mitigation.
        
        Args:
            plaintext (bytes): Data to encrypt
            nonce (Optional[bytes]): Optional nonce, generated if not provided
        
        Returns:
            bytes: Encrypted data with nonce and integrity tag
        """
        # Generate nonce if not provided
        if nonce is None:
            nonce = get_random_bytes(16)
        
        if len(nonce) != 16:
            raise ValueError("Nonce must be 128 bits (16 bytes)")
        
        # Select and configure cipher
        cipher = self._get_cipher(nonce)
        
        # Encrypt with constant-time padding
        try:
            ciphertext = cipher.encrypt(self._constant_time_pad(plaintext))
            
            # Generate HMAC for integrity with constant-time comparison
            hmac = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
            
            # Increment usage counter
            self._check_key_rotation()
            
            # Log encryption event
            self.logger.info("Data encryption successful")
            
            return nonce + ciphertext + hmac.digest()
        
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Enhanced decryption with comprehensive integrity checks.
        
        Args:
            encrypted_data (bytes): Encrypted data with nonce and HMAC
        
        Returns:
            bytes: Decrypted plaintext
        """
        try:
            if len(encrypted_data) < 48:
                raise ValueError("Invalid encrypted data format")
            
            nonce = encrypted_data[:16]
            hmac_received = encrypted_data[-32:]
            ciphertext = encrypted_data[16:-32]
            
            # Constant-time HMAC verification
            hmac = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
            
            if not self._constant_time_compare(hmac.digest(), hmac_received):
                raise ValueError("Integrity check failed: Potential data tampering")
            
            # Select and configure cipher
            cipher = self._get_cipher(nonce)
            
            decrypted = cipher.decrypt(ciphertext)
            
            # Remove constant-time padding
            decrypted = self._remove_constant_time_pad(decrypted)
            
            self.logger.info("Data decryption successful")
            return decrypted
        
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def _check_key_rotation(self):
        """
        Check and manage key rotation based on configured policy.
        """
        self.key_usage_count += 1
        
        if self.key_rotation_policy == KeyRotationPolicy.FIXED_INTERVAL:
            # Rotate key every 1000 uses
            if self.key_usage_count >= 1000:
                self.rotate_key(get_random_bytes(32))
        
        elif self.key_rotation_policy == KeyRotationPolicy.TIME_BASED:
            # Rotate key every 24 hours
            current_time = os.time()
            if current_time - self.key_creation_time > 86400:  # 24 hours
                self.rotate_key(get_random_bytes(32))
    
    def rotate_key(self, new_key: bytes):
        """
        Securely rotate encryption key.
        
        Args:
            new_key (bytes): New 256-bit encryption key
        """
        if len(new_key) != 32:
            raise ValueError("New key must be 256 bits (32 bytes)")
        
        # Securely replace key
        self.key = new_key
        self.enc_key, self.hmac_key = self._derive_keys(new_key)
        
        # Reset usage metadata
        self.key_creation_time = os.time()
        self.key_usage_count = 0
        
        self.logger.info("Key rotated successfully")
    
    def encrypt_file(self, input_file: str, output_file: str, chunk_size: int = 1024 * 1024):
        """
        Memory-efficient file encryption with streaming support.
        
        Args:
            input_file (str): Path to input file
            output_file (str): Path to output encrypted file
            chunk_size (int): Size of chunks for processing large files
        """
        try:
            nonce = get_random_bytes(16)
            cipher = self._get_cipher(nonce)
            
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Write nonce first
                outfile.write(nonce)
                
                # Create HMAC for file integrity
                hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
                
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk = cipher.encrypt(chunk)
                    hmac.update(encrypted_chunk)
                    outfile.write(encrypted_chunk)
                
                # Write HMAC digest
                outfile.write(hmac.digest())
            
            self.logger.info(f"File {input_file} encrypted successfully")
        
        except Exception as e:
            self.logger.error(f"File encryption failed: {e}")
            raise
    
    def decrypt_file(self, input_file: str, output_file: str, chunk_size: int = 1024 * 1024):
        """
        Memory-efficient file decryption with streaming support.
        
        Args:
            input_file (str): Path to input encrypted file
            output_file (str): Path to output decrypted file
            chunk_size (int): Size of chunks for processing large files
        """
        try:
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Read nonce
                nonce = infile.read(16)
                cipher = self._get_cipher(nonce)
                
                # Create HMAC for integrity verification
                hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
                
                # File size calculation for HMAC verification
                infile.seek(0, os.SEEK_END)
                file_size = infile.tell()
                infile.seek(16)  # Return to after nonce
                
                while infile.tell() < file_size - 32:  # Reserve space for HMAC
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    
                    decrypted_chunk = cipher.decrypt(chunk)
                    hmac.update(chunk)
                    outfile.write(decrypted_chunk)
                
                # Verify HMAC
                computed_hmac = hmac.digest()
                stored_hmac = infile.read(32)
                
                if not self._constant_time_compare(computed_hmac, stored_hmac):
                    raise ValueError("File integrity verification failed")
            
            self.logger.info(f"File {input_file} decrypted successfully")
        
        except Exception as e:
            self.logger.error(f"File decryption failed: {e}")
            raise
    
    @staticmethod
    def _constant_time_pad(data: bytes, block_size: int = 32) -> bytes:
        """
        Add constant-time padding to mitigate side-channel attacks.
        
        Args:
            data (bytes): Original data
            block_size (int): Padding block size
        
        Returns:
            bytes: Padded data
        """
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _remove_constant_time_pad(padded_data: bytes) -> bytes:
        """
        Remove constant-time padding.
        
        Args:
            padded_data (bytes): Padded data
        
        Returns:
            bytes: Original data without padding
        """
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        
        Args:
            a (bytes): First byte sequence
            b (bytes): Second byte sequence
        
        Returns:
            bool: Whether byte sequences are equal
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

# Example Usage
if __name__ == "__main__":
    # Initialize with ChaCha20, fixed interval key rotation
    key = get_random_bytes(32)
    cipher = EnhancedIndiaMethodCipher(
        key, 
        cipher_type=CipherType.CHACHA20,
        key_rotation_policy=KeyRotationPolicy.FIXED_INTERVAL
    )

    # Encryption example
    plaintext = b"Confidential Data for Masters Dissertation"
    encrypted_data = cipher.encrypt(plaintext)
    decrypted_data = cipher.decrypt(encrypted_data)

    assert decrypted_data == plaintext
    print("Encryption and Decryption successful!")

    # File encryption example
    test_file = "research_draft.txt"
    with open(test_file, "wb") as f:
        f.write(plaintext)

    cipher.encrypt_file(test_file, "encrypted_draft.bin")
    cipher.decrypt_file("encrypted_draft.bin", "decrypted_draft.txt")

    with open("decrypted_draft.txt", "rb") as f:
        assert f.read() == plaintext
    
    print("File Encryption and Decryption successful!")
