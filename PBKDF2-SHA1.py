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

def validate_password_strength(self, password: str) -> None:
        """
        Validate password strength:
        - min length 8
        - uppercase, lowercase, digit, special char
        """
        if len(password) < 8:
            raise PasswordError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", password):
            raise PasswordError("Password must include at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            raise PasswordError("Password must include at least one lowercase letter.")
        if not re.search(r"[0-9]", password):
            raise PasswordError("Password must include at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise PasswordError("Password must include at least one special character.")


def hash_password(self, password: str) -> str:
        """Hash a password with PBKDF2-HMAC and return a JSON string with metadata."""
        self.validate_password_strength(password)
        salt = os.urandom(self.salt_length)
        dk = hashlib.pbkdf2_hmac(self.algorithm, password.encode(), salt, self.iterations, dklen=self.hash_length)
        metadata = {
            "v": self.CURRENT_VERSION,
            "algo": self.algorithm,
            "iter": self.iterations,
            "salt": binascii.hexlify(salt).decode(),
            "hash": binascii.hexlify(dk).decode()
        }
        return json.dumps(metadata)

def verify_password(self, stored_data: str, provided_password: str) -> bool:
        """
        Verify a password against stored data.
        Automatically rehash if parameters are outdated.
        """
        try:
            data: Dict[str, Any] = json.loads(stored_data)
            required_keys = {"v", "algo", "iter", "salt", "hash"}
            if not required_keys.issubset(data.keys()):
                logging.error("Invalid stored password format.")
                return False

            salt = binascii.unhexlify(data["salt"])
            stored_hash = binascii.unhexlify(data["hash"])
            new_hash = hashlib.pbkdf2_hmac(
                data["algo"],
                provided_password.encode(),
                salt,
                int(data["iter"]),
                dklen=len(stored_hash)
            )

            valid = hmac.compare_digest(stored_hash, new_hash)
            if valid and (int(data["iter"]) != self.iterations or data["algo"] != self.algorithm):
                logging.info("Rehashing password with new parameters...")
                return "rehash_needed"
            return valid
        except (json.JSONDecodeError, KeyError, binascii.Error) as e:
            logging.error(f"Failed to verify password: {e}")
            return False