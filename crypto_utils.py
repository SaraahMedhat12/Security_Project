from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
import os

# ------------------ Argon2 Password Hashing ------------------ #

ph = PasswordHasher()

def argon2_hash_password(password):
    """
    Hashes the given password using Argon2.
    Returns: hashed_password (str)
    """
    return ph.hash(password)

def argon2_verify_password(password, hashed_password):
    """
    Verifies a password against the given Argon2 hash.
    Returns: True if match, else False
    """
    try:
        return ph.verify(hashed_password, password)
    except Exception:
        return False

# ------------------ PBKDF2 Functions ------------------ #

def hash_password(password):
    """
    Hashes a password using PBKDF2 (SHA-256).
    Returns: (hashed_bytes, salt)
    """
    salt = os.urandom(16)
    hashed = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    ).derive(password.encode())
    return hashed, salt

def verify_password(password, hashed_password, salt):
    """
    Verifies password against a PBKDF2 hash and salt.
    Returns: True if valid, else False
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), hashed_password)
        return True
    except Exception:
        return False

def derive_key_from_password(password, salt):
    """
    Derives a symmetric AES key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ------------------ Encryption & Decryption ------------------ #

def encrypt_data(key, plaintext):
    """
    Encrypts plaintext (str or bytes) using AES-CFB.
    Returns: IV + ciphertext (bytes)
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_data(key, iv_ciphertext):
    """
    Decrypts data encrypted with encrypt_data.
    Expects: IV + ciphertext (bytes)
    Returns: decrypted bytes
    """
    if len(iv_ciphertext) < 16:
        raise ValueError("Corrupted file: No IV found.")
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ------------------ SHA-256 Hash ------------------ #

def hash_data(data):
    """
    Returns SHA-256 hash of the given data (bytes).
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()
