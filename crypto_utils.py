import secrets
import string
from cryptography.fernet import Fernet
import bcrypt

#Password generation function
def generate_pass() -> str:
    """Generates a secure random password between 10 and 20 characters."""
    # Define characters with mix of character pools
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    
    # Determine a secure random length between 10 and 20
    length = secrets.choice(range(10, 21))
    
    # Cryptographically secure random assembly
    return "".join(secrets.choice(characters) for _ in range(length))

 #Master Password Hashing (One-Way)
def hash_master_password(password: str) -> str:
    """Hashes the master password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_master_password(password: str, hashed: str) -> bool:
    """Verifies a login attempt against the stored master hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Vault Encryption (Two-Way AES via Fernet)
# NOTE: In production, you would derive this key from the user's master password 
# using PBKDF2, or securely store a master key in an environment variable.
def generate_encryption_key() -> bytes:
    return Fernet.generate_key()

def encrypt_password(plain_password: str, key: bytes) -> str:
    """Encrypts a credential password using AES."""
    f = Fernet(key)
    return f.encrypt(plain_password.encode('utf-8')).decode('utf-8')

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    """Decrypts a credential password back to plain text."""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode('utf-8')).decode('utf-8')

