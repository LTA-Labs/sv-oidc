from cryptography.fernet import Fernet
import base64

from app.config import settings

_cipher = None


def get_cipher():
    global _cipher
    if _cipher is None:
        # Convert the encryption key to a valid Fernet key
        key = base64.urlsafe_b64encode(settings.ENCRYPTION_KEY.encode().ljust(32)[:32])
        _cipher = Fernet(key)
    return _cipher


def encrypt_data(data: bytes) -> bytes:
    """
    Encrypt data using Fernet symmetric encryption.
    """
    cipher = get_cipher()
    return cipher.encrypt(data)


def decrypt_data(encrypted_data: bytes) -> bytes:
    """
    Decrypt data using Fernet symmetric encryption.
    """
    cipher = get_cipher()
    return cipher.decrypt(encrypted_data)
