import os
import hashlib
import binascii
import hmac
import secrets

DEFAULT_ITERATIONS = 100_000
SALT_SIZE = 16

def generate_salt(length: int = SALT_SIZE) -> bytes:
    """Krijon salt të rastësishëm dhe të sigurt."""
    return secrets.token_bytes(length)

def hash_password_pbkdf2_sha1(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """
    Gjeneron hash për një fjalëkalim duke përdorur PBKDF2-HMAC-SHA1.
    Kthen një string në format: salt$hash
    """
    if not isinstance(password, str):
        raise TypeError("Password duhet të jetë string.")

    salt = generate_salt()
