<table border="0">
 <tr>
    <td style="width:300px; vertical-align:middle; text-align:center;">
      <img src="https://upload.wikimedia.org/wikipedia/commons/e/e1/University_of_Prishtina_logo.svg" 
           alt="University Logo" 
           style="width:250px; height:auto;" />
    </td>
    <td style="vertical-align:middle; padding-left:20px;">
      <h2><strong>Universiteti i Prishtinës</strong></h2>
      <h3>Fakulteti i Inxhinierisë Elektrike dhe Kompjuterike</h3>
      <p>Inxhinieri Kompjuterike dhe Softuerike - Programi Master</p>
      <p><strong>Profesor:</strong> Prof. Dr. Blerim Rexha</p>
      <p><strong>Asistent:</strong> Dr.Sc. Mërgim H. HOTI</p>
    </td>
 </tr>
</table>


# Introduction

The purpose of this project is to demonstrate how passwords can be securely stored and verified using the PBKDF2-SHA1 algorithm in Python.  
Traditional password hashing methods such as MD5 or SHA1 alone are vulnerable to brute-force and rainbow-table attacks. PBKDF2 (Password-Based Key Derivation Function 2) increases security by applying a cryptographic hash multiple times and adding a random salt, making attacks computationally expensive and impractical.

This implementation shows how to generate a strong salted hash for a user’s password and later verify it safely without ever storing or comparing the password in plain text.

## Algorithm Overview

PBKDF2-HMAC-SHA1 works as follows:

  1. A random salt is generated for each password using secrets.token_bytes().

  2. The password and salt are processed through PBKDF2 using HMAC-SHA1 as the pseudorandom function.

  3. The algorithm performs the hashing process multiple iterations (e.g., 100,000 times by default).

  4. The resulting derived key (hash) is stored together with the salt in the format:

    salt$hash


  5. When verifying, the salt is extracted, the same process is repeated on the attempted password, and both hashes are compared using a constant-time comparison (hmac.compare_digest) to prevent timing attacks.

## Code Explanaion

1. Constants and Libraries

  ```python
  DEFAULT_ITERATIONS = 100_000
  SALT_SIZE = 16
  ```
  
These define the number of iterations (strength of the hashing) and the length of the salt in bytes.
Libraries used: hashlib, binascii, hmac, os, and secrets.

2. Salt Generation

  ```python
  def generate_salt(length: int = SALT_SIZE) -> bytes:
    return secrets.token_bytes(length)
  ```
  
Generates a cryptographically secure random salt. Using secrets ensures unpredictability and security.

3. Hashing Function
   
  ```python
  def hash_password_pbkdf2_sha1(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = generate_salt()
    dk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations)
    salt_hex = binascii.hexlify(salt).decode('utf-8')
    dk_hex = binascii.hexlify(dk).decode('utf-8')
    return f"{salt_hex}${dk_hex}"
  ```

This function converts the password into a secure hash using PBKDF2-HMAC-SHA1 and returns it in a readable hex format, separated by $.

4. Verification Function

  ```python
  def verify_password_pbkdf2_sha1(stored: str, password_attempt: str, iterations: int = DEFAULT_ITERATIONS) -> bool:
    salt_hex, dk_hex = stored.split('$')
    salt = binascii.unhexlify(salt_hex)
    dk_stored = binascii.unhexlify(dk_hex)
    dk_attempt = hashlib.pbkdf2_hmac('sha1', password_attempt.encode('utf-8'), salt, iterations)
    return hmac.compare_digest(dk_stored, dk_attempt)
  ```

This checks if the user-entered password matches the stored hash by recalculating and comparing the results securely.

5. Example of Usage

  ```python
  if __name__ == "__main__":
    password = input("Enter a password to hash: ")
    stored_hash = hash_password_pbkdf2_sha1(password)
    print(f"Stored hash: {stored_hash}")

    attempt = input("Enter password again for verification: ")
    if verify_password_pbkdf2_sha1(stored_hash, attempt):
        print("Password is correct!")
    else:
        print("Password is incorrect.")
  ```

This shows how the program can hash a user’s password and verify it safely without exposing the original value.

## Why PBKDF2-SHA1 Matters

PBKDF2 strengthens password protection by:

  - Applying thousands of iterations, slowing down brute-force attacks.

  - Using a unique salt per user, preventing rainbow-table reuse.

  - Storing only the salted hash, never the plaintext password.

  - Ensuring constant-time comparison to avoid timing attacks.

This makes PBKDF2 a strong and NIST-approved key derivation method, widely used in modern security systems and password managers.

