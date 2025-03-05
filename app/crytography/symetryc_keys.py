import base64
import hashlib
import secrets
import traceback

from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AESCrypto:
    def __init__(self, password: bytes | None = None, salt: bytes | None = None):
        """
        Initialize AES encryption with optional password and salt
        If not provided, generates new ones
        """
        # Generate or use provided salt
        self.salt = salt or secrets.token_bytes(16)

        # Generate key from password using PBKDF2
        if password is None:
            password = secrets.token_bytes(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend(),
        )
        self.key = kdf.derive(password)

    def dump_key(self, filename="aes_key.bin", protection_password: str | None = None):
        """
        Dump the key and salt to a file with optional password protection

        :param filename: Path to save the key file
        :param protection_password: Optional password to encrypt the key file
        """
        # Prepare data to write
        key_data = self.salt + self.key

        if protection_password:
            # Hash the protection password
            protection_salt = secrets.token_bytes(16)
            protection_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=protection_salt,
                iterations=100000,
                backend=default_backend(),
            )
            protection_key = protection_kdf.derive(protection_password.encode())

            # Use Fernet for symmetric encryption of the key file
            f = Fernet(base64.urlsafe_b64encode(protection_key))
            encrypted_data = f.encrypt(key_data)

            with open(filename, "wb") as file:
                file.write(protection_salt)
                file.write(encrypted_data)
            print(f"Key dumped with password protection to {filename}")
        else:
            # Unencrypted dump
            with open(filename, "wb") as file:
                file.write(key_data)
            print(f"Key dumped unencrypted to {filename}")

    @classmethod
    def load_key(cls, filename="aes_key.bin", protection_password: str | None = None):
        """
        Load key and salt from a file with optional password protection

        :param filename: Path to the key file
        :param protection_password: Optional password to decrypt the key file
        :return: AESCrypto instance with loaded key
        """
        with open(filename, "rb") as file:
            protection_salt = file.read(16)
            file_data = file.read()

        if protection_password:
            # Hash the protection password
            protection_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=protection_salt,
                iterations=100000,
                backend=default_backend(),
            )
            protection_key = protection_kdf.derive(protection_password.encode())

            # Use Fernet to decrypt
            try:
                f = Fernet(base64.urlsafe_b64encode(protection_key))
                decrypted_data = f.decrypt(file_data)
            except Exception as e:
                traceback.print_exc()
                raise ValueError(f"Decryption error: {e}") from e
        else:
            decrypted_data = file_data

        # Extract salt and key
        salt = decrypted_data[:16]
        key = decrypted_data[16:]

        # Create instance with loaded salt and key
        instance = cls.__new__(cls)
        instance.salt = salt
        instance.key = key
        return instance

    def encrypt(self, plaintext: str):
        """
        Encrypt plaintext with HMAC for integrity check
        """
        # Generate a random IV
        iv = secrets.token_bytes(16)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Pad the plaintext (PKCS7 padding)
        padded_text = self._pad(plaintext.encode())

        # Encrypt
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()

        # Create HMAC for integrity check
        hmac = self._create_hmac(iv + ciphertext)

        # Return IV + ciphertext + HMAC
        return base64.b64encode(iv + ciphertext + hmac)

    def decrypt(self, input_encrypted_data: str):
        """
        Decrypt with integrity verification
        Raises ValueError if decryption fails
        """
        try:
            # Decode base64
            encrypted_data: bytes = base64.b64decode(input_encrypted_data)

            # Extract components
            iv = encrypted_data[:16]
            hmac_length = 32  # SHA-256 HMAC length
            hmac = encrypted_data[-hmac_length:]
            ciphertext = encrypted_data[16:-hmac_length]

            # Verify HMAC first
            if not self._verify_hmac(iv + ciphertext, hmac):
                raise ValueError("Integrity check failed. Wrong key or tampered data.")

            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # Decrypt and unpad
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return self._unpad(decrypted).decode()

        except (ValueError, InvalidKey) as e:
            # This will catch various decryption errors
            print(f"Decryption error: {e}")
            return None

    def _create_hmac(self, data):
        """
        Create HMAC for data integrity
        """
        h = hashlib.sha256()
        h.update(data)
        h.update(self.key)  # Key-dependent HMAC
        return h.digest()

    def _verify_hmac(self, data, provided_hmac):
        """
        Verify HMAC integrity
        """
        calculated_hmac = self._create_hmac(data)
        return (
            hashlib.sha256(calculated_hmac).digest()
            == hashlib.sha256(provided_hmac).digest()
        )

    def _pad(self, s):
        """PKCS7 padding"""
        padding_length = 16 - (len(s) % 16)
        padding = bytes([padding_length] * padding_length)
        return s + padding

    def _unpad(self, s):
        """Remove PKCS7 padding"""
        padding_length = s[-1]
        return s[:-padding_length]


__symmetric_cipher: AESCrypto | None = None


def load_symmetric_key(path: str, password: str) -> None:
    global __symmetric_cipher
    __symmetric_cipher = AESCrypto.load_key(path, password)


def get_symmetric_cipher() -> AESCrypto:
    if __symmetric_cipher is None:
        raise ValueError("Cipher keys not loaded.")
    return __symmetric_cipher
