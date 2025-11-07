import secrets

DEFAULT_ITERATIONS = 100_000
SALT_SIZE = 16

def generate_salt(length: int = SALT_SIZE) -> bytes:
    """Krijon salt të rastësishëm dhe të sigurt."""
    return secrets.token_bytes(length)