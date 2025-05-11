import json
import os
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher

# --- PBKDF2-based password hashing ---
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Secure random salt

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    hashed = kdf.derive(password.encode())

    return base64.b64encode(hashed).decode(), base64.b64encode(salt).decode()

def verify_password(password, hashed_password_b64, salt_b64):
    salt = base64.b64decode(salt_b64)
    hashed_password = base64.b64decode(hashed_password_b64)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )

    try:
        kdf.verify(password.encode(), hashed_password)
        return True
    except Exception:
        return False

# --- Password → AES key (legacy support) ---
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# --- Hash → AES key (modern system) ---
def derive_aes_key_from_password_hash(password_hash: bytes, salt: bytes) -> bytes:
    """Second-level PBKDF2 key derivation from the stored password hash."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password_hash)

# ✅ --- Load user data from plain users.json ---
def get_user_derived_aes_key(username: str) -> bytes:
    with open("users.json", "r") as f:
        users = json.load(f)

    if username not in users:
        raise ValueError(f"User '{username}' not found in users.json")

    password_hash_b64 = users[username]["hashed_pw"]
    salt_b64 = users[username]["salt"]

    password_hash = base64.b64decode(password_hash_b64)
    salt = base64.b64decode(salt_b64)

    return derive_aes_key_from_password_hash(password_hash, salt)

# --- File integrity hash ---
def compute_file_hash(path: str) -> str:
    """Return hex-encoded SHA256 of the file at `path`."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

# --- AES file encryption ---
def encrypt_file(in_path: str, out_path: str, key: bytes) -> bytes:
    """Encrypt in_path → out_path with AES-CFB; returns the IV."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(iv)
        for chunk in iter(lambda: fin.read(4096), b""):
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())
    return iv

# --- AES file decryption ---
def decrypt_file(in_path: str, out_path: str, key: bytes):
    """Read IV from in_path, decrypt rest, write to out_path."""
    with open(in_path, "rb") as fin:
        iv = fin.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        with open(out_path, "wb") as fout:
            for chunk in iter(lambda: fin.read(4096), b""):
                fout.write(decryptor.update(chunk))
            fout.write(decryptor.finalize())

# --- Argon2 password support (used by peer) ---
ph = PasswordHasher()

def argon2_hash_password(password: str) -> str:
    return ph.hash(password)

def argon2_verify_password(password: str, hashed_password: str) -> bool:
    try:
        return ph.verify(hashed_password, password)
    except Exception:
        return False

# --- Generic AES data encryption/decryption ---
def encrypt_data(key: bytes, plaintext: bytes | str) -> bytes:
    """Encrypt a string or bytes using AES-CFB with random IV. Returns IV + ciphertext."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_data(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-CFB data assuming IV is prepended (16 bytes)."""
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
