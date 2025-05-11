# File: user_manager.py

import json
import os
from crypto_utils import (
    argon2_hash_password,
    argon2_verify_password,
    derive_key_from_password,
    encrypt_data,
    decrypt_data
)

# File paths
USER_FILE = "users.json.enc"
MASTER_HASH_FILE = "master.hash"
SALT_FILE = "salt.bin"

def setup_master_password(password):
    """Set up and store master password hash and salt."""
    if os.path.exists(MASTER_HASH_FILE):
        print("Master password already setup.")
        return
    hashed = argon2_hash_password(password)
    with open(MASTER_HASH_FILE, "w") as f:
        f.write(hashed)
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    print("Master password setup completed.")

def verify_master_password(password):
    """Verify the provided master password against stored hash."""
    if not os.path.exists(MASTER_HASH_FILE):
        print("No master password found.")
        return False
    with open(MASTER_HASH_FILE, "r") as f:
        hashed = f.read()
    return argon2_verify_password(password, hashed)

def load_users(password):
    """Load and decrypt users from encrypted JSON."""
    if not os.path.exists(SALT_FILE):
        print("Salt file missing.")
        return None, None
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    key = derive_key_from_password(password, salt)

    if not os.path.exists(USER_FILE):
        return {}, key  # Return empty if file not created yet

    with open(USER_FILE, "rb") as f:
        encrypted_data = f.read()
    try:
        decrypted = decrypt_data(key, encrypted_data)
        return json.loads(decrypted), key
    except Exception:
        print("Decryption failed. Invalid password or corrupted file.")
        return None, None

def save_users(users, key):
    """Encrypt and save user data."""
    data = json.dumps(users)
    encrypted = encrypt_data(key, data)
    with open(USER_FILE, "wb") as f:
        f.write(encrypted)
