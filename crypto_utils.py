# crypto_utils.py

import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ===========================
# Phase 1 Note:
# No encryption/authentication needed
# These functions are kept ready for Phase 2+
# ===========================

# Placeholder for Argon2id-like functionality
# Note: cryptography library doesn't expose Argon2id hash(). We'll simulate.

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode())
    return hashed_password, salt

def verify_password(password, hashed_password, salt):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        kdf.verify(password.encode(), hashed_password)
        return True
    except Exception:
        return False

def derive_key_from_password(password, salt):
    """
    Derives a 256-bit symmetric key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())
