import os
import enum
import logging
from typing import Optional, Union
from Crypto.Cipher import ChaCha20, AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Random import get_random_bytes
import hashlib
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import struct

class CipherType(enum.Enum):
    CHACHA20 = enum.auto()
    AES_GCM = enum.auto()

class KeyRotationPolicy(enum.Enum):
    FIXED_INTERVAL = enum.auto()
    USAGE_BASED = enum.auto()
    TIME_BASED = enum.auto()

class ContextualEntropyInjection:
    """Implementation of Contextual Entropy Injection for Enhanced India Method Cipher."""
    def __init__(self, base_key: bytes, rounds: int = 3):
        self.base_key = base_key
        self.rounds = rounds
        self.block_size = 16

    def analyze_data_patterns(self, data: bytes) -> dict:
        patterns = {}
        byte_freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        patterns['byte_entropy'] = -np.sum((byte_freq / len(data)) * 
                                     np.log2(byte_freq / len(data) + 1e-10))
        chunk_size = min(1024, len(data) // 10 or 1)
        chunk_entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            chunk_freq = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
            chunk_entropy = -np.sum((chunk_freq / len(chunk)) * 
                                 np.log2(chunk_freq / len(chunk) + 1e-10))
            chunk_entropies.append(chunk_entropy)
        patterns['chunk_entropy_variance'] = np.var(chunk_entropies)
        patterns['chunk_entropy_mean'] = np.mean(chunk_entropies)
        patterns['repeating_patterns'] = self._find_repeating_patterns(data)
        patterns['data_length'] = len(data)
        return patterns

    def _find_repeating_patterns(self, data: bytes, min_length: int = 3, max_length: int = 8) -> float:
        patterns = {}
        for pattern_len in range(min_length, max_length + 1):
            pattern_counts = {}
            for i in range(len(data) - pattern_len + 1):
                pattern = data[i:i+pattern_len]
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            significant_patterns = {k: v for k, v in pattern_counts.items() if v >= 3}
            if significant_patterns:
                patterns[pattern_len] = len(significant_patterns)
        return sum(patterns.values()) / len(data) if patterns else 0

    def derive_contextual_key(self, data: bytes, metadata: Optional[dict] = None) -> bytes:
        patterns = self.analyze_data_patterns(data)
        context_seed = struct.pack(
            'ddddd',
            patterns['byte_entropy'],
            patterns['chunk_entropy_variance'],
            patterns['chunk_entropy_mean'],
            patterns['repeating_patterns'],
            patterns['data_length']
        )
        if metadata:
            metadata_str = str(sorted(metadata.items()))
            context_seed += hashlib.sha256(metadata_str.encode()).digest()
        contextual_key = self.base_key
        for _ in range(self.rounds):
            mixed_input = contextual_key + context_seed
            contextual_key = hashlib.sha256(mixed_input).digest()
        return contextual_key

    def create_transformation_matrix(self, contextual_key: bytes, data_size: int) -> list:
        np.random.seed(int.from_bytes(contextual_key[:4], byteorder='big'))
        transforms = []
        blocks = data_size // self.block_size + (1 if data_size % self.block_size else 0)
        for i in range(blocks):
            block_key = hashlib.sha256(contextual_key + i.to_bytes(4, byteorder='big')).digest()
            transform = {
                'operation': np.random.choice(['xor', 'rotate', 'substitute']),
                'key': block_key,
                'parameter': np.random.randint(1, 16)
            }
            transforms.append(transform)
        return transforms

class EnhancedIndiaMethodCipher:
    """Enhanced India Method Cipher with Contextual Entropy Injection."""
    def __init__(
        self,
        key: bytes,
        cipher_type: CipherType = CipherType.CHACHA20,
        key_rotation_policy: Optional[KeyRotationPolicy] = None,
        log_level: int = logging.INFO,
        entropy_rounds: int = 3
    ):
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)

        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")

        self.key = key
        self.cipher_type = cipher_type
        self.key_rotation_policy = key_rotation_policy
        self.key_creation_time = os.time()
        self.key_usage_count = 0
        self.context_injector = ContextualEntropyInjection(key, rounds=entropy_rounds)
        self.enc_key, self.hmac_key = self._derive_keys(key)
        self.logger.info("Cipher initialized with contextual entropy injection")

    def _derive_keys(self, master_key: bytes, data: Optional[bytes] = None, metadata: Optional[dict] = None) -> tuple[bytes, bytes]:
        salt = get_random_bytes(16)
        enc_key = scrypt(
            password=master_key,
            salt=salt,
            key_len=32,
            N=2**14,
            r=8,
            p=1
        )
        hmac_key = HKDF(
            master_key=master_key,
            key_len=32,
            salt=b"hmac_derivation",
            hashmod=SHA256
        )
        if data is not None:
            contextual_key = self.context_injector.derive_contextual_key(data, metadata)
            enc_key = bytes([e ^ c for e, c in zip(enc_key, contextual_key)])
            hmac_key = bytes([h ^ c for h, c in zip(hmac_key, contextual_key)])
        return enc_key, hmac_key

    def _get_cipher(self, nonce: bytes) -> Union[ChaCha20.ChaCha20Cipher, AES.AESCipher]:
        if self.cipher_type == CipherType.CHACHA20:
            return ChaCha20.new(key=self.enc_key, nonce=nonce)
        elif self.cipher_type == CipherType.AES_GCM:
            return AES.new(self.enc_key, AES.MODE_GCM, nonce=nonce)
        else:
            raise ValueError(f"Unsupported cipher type: {self.cipher_type}")

    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None, metadata: Optional[dict] = None) -> bytes:
        if nonce is None:
            nonce = get_random_bytes(16)
        if len(nonce) != 16:
            raise ValueError("Nonce must be 128 bits (16 bytes)")

        self.enc_key, self.hmac_key = self._derive_keys(self.key, plaintext, metadata)
        transformations = self.context_injector.create_transformation_matrix(self.enc_key, len(plaintext))
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        transformed_data = b''
        for i in range(0, len(padded_data), self.context_injector.block_size):
            block = padded_data[i:i+self.context_injector.block_size]
            transform = transformations[i // self.context_injector.block_size]
            if transform['operation'] == 'xor':
                block = bytes([b ^ transform['key'][j % len(transform['key'])] 
                              for j, b in enumerate(block)])
            elif transform['operation'] == 'rotate':
                block = block[transform['parameter']:] + block[:transform['parameter']]
            elif transform['operation'] == 'substitute':
                sub_table = [((j + transform['key'][j % len(transform['key'])]) % 256) for j in range(256)]
                block = bytes([sub_table[b] for b in block])
            transformed_data += block

        cipher = self._get_cipher(nonce)
        ciphertext = cipher.encrypt(transformed_data)
        hmac = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
        self._check_key_rotation()
        self.logger.info("Data encryption successful with contextual entropy")
        context_header = hashlib.sha256(self.enc_key).digest()[:8]
        return nonce + context_header + ciphertext + hmac.digest()

    def decrypt(self, encrypted_data: bytes, metadata: Optional[dict] = None) -> bytes:
        if len(encrypted_data) < 56:
            raise ValueError("Invalid encrypted data format")

        nonce = encrypted_data[:16]
        context_header = encrypted_data[16:24]
        hmac_received = encrypted_data[-32:]
        ciphertext = encrypted_data[24:-32]

        self.enc_key, self.hmac_key = self._derive_keys(self.key, metadata=metadata)
        hmac = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
        if not self._constant_time_compare(hmac.digest(), hmac_received):
            raise ValueError("Integrity check failed: Potential data tampering")

        cipher = self._get_cipher(nonce)
        transformed_data = cipher.decrypt(ciphertext)
        transformations = self.context_injector.create_transformation_matrix(self.enc_key, len(transformed_data))

        decrypted_data = b''
        for i in range(0, len(transformed_data), self.context_injector.block_size):
            block = transformed_data[i:i+self.context_injector.block_size]
            transform = transformations[i // self.context_injector.block_size]
            if transform['operation'] == 'xor':
                block = bytes([b ^ transform['key'][j % len(transform['key'])] 
                              for j, b in enumerate(block)])
            elif transform['operation'] == 'rotate':
                block = block[-transform['parameter']:] + block[:-transform['parameter']]
            elif transform['operation'] == 'substitute':
                sub_table = [((j + transform['key'][j % len(transform['key'])]) % 256) for j in range(256)]
                inv_table = [0] * 256
                for j, v in enumerate(sub_table):
                    inv_table[v] = j
                block = bytes([inv_table[b] for b in block])
            decrypted_data += block

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        self.logger.info("Data decryption successful")
        return plaintext

    def _check_key_rotation(self):
        self.key_usage_count += 1
        if self.key_rotation_policy == KeyRotationPolicy.FIXED_INTERVAL and self.key_usage_count >= 1000:
            self.rotate_key(get_random_bytes(32))
        elif self.key_rotation_policy == KeyRotationPolicy.TIME_BASED:
            if os.time() - self.key_creation_time > 86400:
                self.rotate_key(get_random_bytes(32))

    def rotate_key(self, new_key: bytes):
        if len(new_key) != 32:
            raise ValueError("New key must be 256 bits (32 bytes)")
        self.key = new_key
        self.enc_key, self.hmac_key = self._derive_keys(new_key)
        self.key_creation_time = os.time()
        self.key_usage_count = 0
        self.context_injector = ContextualEntropyInjection(new_key, rounds=self.context_injector.rounds)
        self.logger.info("Key rotated successfully")

    def encrypt_file(self, input_file: str, output_file: str, metadata: Optional[dict] = None, chunk_size: int = 1024 * 1024):
        nonce = get_random_bytes(16)
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            data = infile.read()
            encrypted_data = self.encrypt(data, nonce, metadata)
            outfile.write(encrypted_data)
        self.logger.info(f"File {input_file} encrypted successfully")

    def decrypt_file(self, input_file: str, output_file: str, metadata: Optional[dict] = None, chunk_size: int = 1024 * 1024):
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            encrypted_data = infile.read()
            decrypted_data = self.decrypt(encrypted_data, metadata)
            outfile.write(decrypted_data)
        self.logger.info(f"File {input_file} decrypted successfully")

    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

if __name__ == "__main__":
    key = get_random_bytes(32)
    cipher = EnhancedIndiaMethodCipher(key, cipher_type=CipherType.CHACHA20)
    plaintext = b"Test Data"
    metadata = {"author": "Joshua"}
    encrypted = cipher.encrypt(plaintext, metadata=metadata)
    decrypted = cipher.decrypt(encrypted, metadata=metadata)
    print(f"Plaintext: {plaintext}, Decrypted: {decrypted}")
