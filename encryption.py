"""
AES Encryption Module for Secure File Sharing Application

This module implements AES-256-GCM encryption for file protection.
Each file is encrypted with a unique key, which is then encrypted
with the application's master key for secure storage.

Security Features:
- AES-256-GCM (Authenticated Encryption)
- Per-file unique encryption keys
- Random IV/nonce for each encryption
- Master key protection for key storage
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESEncryption:
    """Handles AES-256-GCM encryption and decryption operations."""

    def __init__(self, master_key: str):
        """
        Initialize the encryption system with the master key.

        Args:
            master_key: The application master key (32 bytes)
        """
        # Derive a proper 256-bit key from the master key using PBKDF2
        self.master_key = self._derive_key(master_key, b'master_key_salt')

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a secure 256-bit key using PBKDF2-HMAC-SHA256.

        Args:
            password: The password/passphrase to derive key from
            salt: Salt for key derivation

        Returns:
            32-byte derived key suitable for AES-256
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def generate_file_key(self) -> bytes:
        """
        Generate a unique random 256-bit key for file encryption.

        Returns:
            32-byte random key
        """
        return os.urandom(32)

    def encrypt_file_key(self, file_key: bytes) -> str:
        """
        Encrypt a file key using the master key.

        Args:
            file_key: The per-file encryption key (32 bytes)

        Returns:
            Base64-encoded encrypted file key string
        """
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        encrypted_key = aesgcm.encrypt(nonce, file_key, None)
        # Store nonce + encrypted key together
        combined = nonce + encrypted_key
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_file_key(self, encrypted_key_str: str) -> bytes:
        """
        Decrypt a file key using the master key.

        Args:
            encrypted_key_str: Base64-encoded encrypted file key

        Returns:
            Original 32-byte file key
        """
        combined = base64.b64decode(encrypted_key_str.encode('utf-8'))
        nonce = combined[:12]
        encrypted_key = combined[12:]
        aesgcm = AESGCM(self.master_key)
        return aesgcm.decrypt(nonce, encrypted_key, None)

    def encrypt_file(self, file_data: bytes, file_key: bytes) -> tuple:
        """
        Encrypt file data using AES-256-GCM with the provided key.

        Args:
            file_data: Raw file bytes to encrypt
            file_key: 32-byte encryption key

        Returns:
            Tuple of (encrypted_data, nonce) where nonce is base64-encoded
        """
        aesgcm = AESGCM(file_key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        encrypted_data = aesgcm.encrypt(nonce, file_data, None)
        return encrypted_data, base64.b64encode(nonce).decode('utf-8')

    def decrypt_file(self, encrypted_data: bytes, nonce_b64: str, file_key: bytes) -> bytes:
        """
        Decrypt file data using AES-256-GCM.

        Args:
            encrypted_data: The encrypted file bytes
            nonce_b64: Base64-encoded nonce used during encryption
            file_key: 32-byte decryption key

        Returns:
            Original decrypted file bytes
        """
        nonce = base64.b64decode(nonce_b64.encode('utf-8'))
        aesgcm = AESGCM(file_key)
        return aesgcm.decrypt(nonce, encrypted_data, None)

    def encrypt_file_stream(self, input_path: str, output_path: str, file_key: bytes) -> str:
        """
        Encrypt a file from disk and save encrypted version.

        Args:
            input_path: Path to the original file
            output_path: Path to save the encrypted file
            file_key: 32-byte encryption key

        Returns:
            Base64-encoded nonce used for encryption
        """
        with open(input_path, 'rb') as f:
            file_data = f.read()

        encrypted_data, nonce_b64 = self.encrypt_file(file_data, file_key)

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return nonce_b64

    def decrypt_file_stream(self, input_path: str, file_key: bytes, nonce_b64: str) -> bytes:
        """
        Decrypt a file from disk.

        Args:
            input_path: Path to the encrypted file
            file_key: 32-byte decryption key
            nonce_b64: Base64-encoded nonce used during encryption

        Returns:
            Decrypted file bytes
        """
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        return self.decrypt_file(encrypted_data, nonce_b64, file_key)

    @staticmethod
    def generate_file_hash(file_data: bytes) -> str:
        """
        Generate SHA-256 hash of file data for integrity verification.

        Args:
            file_data: File bytes to hash

        Returns:
            Hexadecimal SHA-256 hash string
        """
        return hashlib.sha256(file_data).hexdigest()
