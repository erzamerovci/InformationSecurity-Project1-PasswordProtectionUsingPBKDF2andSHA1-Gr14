import hashlib, binascii, secrets, hmac
DEFAULT_ITERATIONS = 100_000
SALT_SIZE = 16

def generate_salt(length=SALT_SIZE) -> bytes:
    return secrets.token_bytes(length)

class PasswordHasher:
    """
    Robust password hashing utility with:
    - PBKDF2-HMAC (SHA1, SHA256, SHA512)
    - Automatic versioning and rehashing
    - Password strength validation
    """

    DEFAULT_ITERATIONS = 250_000
    DEFAULT_SALT_LENGTH = 16
    DEFAULT_HASH_LENGTH = 32
    SUPPORTED_ALGORITHMS = {"sha1", "sha256", "sha512"}
    CURRENT_VERSION = 1
    
def __init__(self, iterations: int = DEFAULT_ITERATIONS, salt_length: int = DEFAULT_SALT_LENGTH,
                 hash_length: int = DEFAULT_HASH_LENGTH, algorithm: str = "sha512"):
        self.iterations = iterations
        self.salt_length = salt_length
        self.hash_length = hash_length
        self.algorithm = algorithm.lower()
        if self.algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm '{algorithm}'.")
