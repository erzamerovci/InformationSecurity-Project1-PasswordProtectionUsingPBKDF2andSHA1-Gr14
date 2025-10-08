import hashlib, binascii, secrets, hmac
DEFAULT_ITERATIONS = 100_000
SALT_SIZE = 16

def generate_salt(length=SALT_SIZE) -> bytes:
    return secrets.token_bytes(length)
