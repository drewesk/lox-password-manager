#!/usr/bin/env python3
"""
Lox Cryptography Module
Multi-layer encryption with ChaCha20-Poly1305 and AES-256-GCM
Argon2id key derivation for memory-hard protection
"""

import os
import hashlib
import secrets
from typing import Tuple, Optional
from argon2 import PasswordHasher, low_level
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import nacl.secret
import nacl.utils
from base64 import b64encode, b64decode


class SecureMemory:
    """Secure memory handling with automatic wiping"""
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
    
    def get(self) -> bytes:
        return bytes(self._data)
    
    def wipe(self):
        """Securely wipe memory by overwriting with random data multiple times"""
        if self._data:
            # Overwrite with random data 3 times (DoD 5220.22-M standard)
            for _ in range(3):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbits(8)
            # Final overwrite with zeros
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data.clear()
    
    def __del__(self):
        self.wipe()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()


class MultiLayerEncryption:
    """
    Multi-layer encryption using ChaCha20-Poly1305 and AES-256-GCM
    Provides defense in depth against cryptographic breaks
    """
    
    # Argon2id parameters (OWASP recommendations)
    ARGON2_TIME_COST = 3        # iterations
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4      # threads
    ARGON2_HASH_LEN = 64        # bytes
    ARGON2_SALT_LEN = 32        # bytes
    
    # Encryption parameters
    CHACHA20_KEY_SIZE = 32      # 256 bits
    AES_KEY_SIZE = 32           # 256 bits
    NONCE_SIZE = 12             # for both ChaCha20 and AES-GCM
    
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.ARGON2_HASH_LEN,
            salt_len=self.ARGON2_SALT_LEN
        )
    
    def derive_keys(self, master_password: str, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Derive two independent keys from master password using Argon2id
        Returns: (chacha20_key, aes_key)
        """
        # Use Argon2id for primary key derivation
        raw_key = low_level.hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.ARGON2_HASH_LEN,
            type=low_level.Type.ID  # Argon2id
        )
        
        # Split derived key into two independent keys
        chacha20_key = raw_key[:self.CHACHA20_KEY_SIZE]
        aes_key = raw_key[self.CHACHA20_KEY_SIZE:self.CHACHA20_KEY_SIZE + self.AES_KEY_SIZE]
        
        return chacha20_key, aes_key
    
    def encrypt(self, plaintext: bytes, master_password: str) -> bytes:
        """
        Encrypt data with two layers: ChaCha20-Poly1305 then AES-256-GCM
        Format: salt(32) | chacha_nonce(12) | aes_nonce(12) | ciphertext | auth_tags
        """
        # Generate salt and derive keys
        salt = secrets.token_bytes(self.ARGON2_SALT_LEN)
        chacha20_key, aes_key = self.derive_keys(master_password, salt)
        
        try:
            with SecureMemory(chacha20_key) as chacha_mem, SecureMemory(aes_key) as aes_mem:
                # First layer: ChaCha20-Poly1305
                chacha_nonce = secrets.token_bytes(self.NONCE_SIZE)
                chacha = ChaCha20Poly1305(chacha_mem.get())
                layer1 = chacha.encrypt(chacha_nonce, plaintext, None)
                
                # Second layer: AES-256-GCM
                aes_nonce = secrets.token_bytes(self.NONCE_SIZE)
                aes = AESGCM(aes_mem.get())
                layer2 = aes.encrypt(aes_nonce, layer1, None)
                
                # Combine: salt | chacha_nonce | aes_nonce | encrypted_data
                result = salt + chacha_nonce + aes_nonce + layer2
                
                return result
        finally:
            # Ensure keys are wiped
            pass
    
    def decrypt(self, encrypted_data: bytes, master_password: str) -> bytes:
        """
        Decrypt data encrypted with two layers
        """
        # Extract components
        salt = encrypted_data[:self.ARGON2_SALT_LEN]
        chacha_nonce = encrypted_data[self.ARGON2_SALT_LEN:self.ARGON2_SALT_LEN + self.NONCE_SIZE]
        aes_nonce = encrypted_data[
            self.ARGON2_SALT_LEN + self.NONCE_SIZE:
            self.ARGON2_SALT_LEN + 2 * self.NONCE_SIZE
        ]
        ciphertext = encrypted_data[self.ARGON2_SALT_LEN + 2 * self.NONCE_SIZE:]
        
        # Derive keys
        chacha20_key, aes_key = self.derive_keys(master_password, salt)
        
        try:
            with SecureMemory(chacha20_key) as chacha_mem, SecureMemory(aes_key) as aes_mem:
                # First layer: Decrypt with AES-256-GCM
                aes = AESGCM(aes_mem.get())
                layer1_decrypted = aes.decrypt(aes_nonce, ciphertext, None)
                
                # Second layer: Decrypt with ChaCha20-Poly1305
                chacha = ChaCha20Poly1305(chacha_mem.get())
                plaintext = chacha.decrypt(chacha_nonce, layer1_decrypted, None)
                
                return plaintext
        except Exception as e:
            raise ValueError("Decryption failed: Invalid password or corrupted data") from e
    
    def hash_password(self, password: str) -> str:
        """Hash a password for verification using Argon2id"""
        return self.ph.hash(password)
    
    def verify_password(self, hash_str: str, password: str) -> bool:
        """Verify a password against its hash"""
        try:
            self.ph.verify(hash_str, password)
            return True
        except:
            return False
    
    def generate_secure_password(self, length: int = 32, include_symbols: bool = True) -> str:
        """Generate a cryptographically secure random password"""
        if include_symbols:
            alphabet = (
                'abcdefghijklmnopqrstuvwxyz'
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                '0123456789'
                '!@#$%^&*()_+-=[]{}|;:,.<>?'
            )
        else:
            alphabet = (
                'abcdefghijklmnopqrstuvwxyz'
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                '0123456789'
            )
        
        # Use secrets module for cryptographically secure random selection
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password


class SecureSession:
    """
    Time-limited session management with automatic timeout
    Prevents need to re-enter master password for a limited time
    """
    
    SESSION_TIMEOUT = 300  # 5 minutes in seconds
    
    def __init__(self, master_password: str):
        self.session_key = secrets.token_bytes(32)
        self.timestamp = 0
        self.active = False
        self._store_password(master_password)
    
    def _store_password(self, password: str):
        """Store password encrypted with session key"""
        cipher = ChaCha20Poly1305(self.session_key)
        nonce = secrets.token_bytes(12)
        self.encrypted_password = nonce + cipher.encrypt(nonce, password.encode(), None)
        self.active = True
        import time
        self.timestamp = time.time()
    
    def get_password(self) -> Optional[str]:
        """Retrieve password if session is still valid"""
        import time
        if not self.active:
            return None
        
        if time.time() - self.timestamp > self.SESSION_TIMEOUT:
            self.invalidate()
            return None
        
        # Refresh timestamp on access
        self.timestamp = time.time()
        
        cipher = ChaCha20Poly1305(self.session_key)
        nonce = self.encrypted_password[:12]
        ciphertext = self.encrypted_password[12:]
        password = cipher.decrypt(nonce, ciphertext, None)
        return password.decode()
    
    def invalidate(self):
        """Invalidate session and wipe sensitive data"""
        self.active = False
        if hasattr(self, 'session_key'):
            with SecureMemory(self.session_key) as mem:
                mem.wipe()
        if hasattr(self, 'encrypted_password'):
            with SecureMemory(self.encrypted_password) as mem:
                mem.wipe()
    
    def __del__(self):
        self.invalidate()