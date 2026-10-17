
import hashlib
import hmac
import secrets
import getpass
import re


# Password policy settings
MIN_LENGTH = 12
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LENGTH = 16
KEY_LENGTH = 32


def validate_password(password):
    """Check a password against the lab's password policy."""
    errors = []

    if len(password) < MIN_LENGTH:
        errors.append(f"Use at least {MIN_LENGTH} characters.")

    if not re.search(r"[a-z]", password):
        errors.append("Include at least one lowercase letter.")

    if not re.search(r"[A-Z]", password):
        errors.append("Include at least one uppercase letter.")

    if not re.search(r"\d", password):
        errors.append("Include at least one number.")

    if not re.search(r"[^a-zA-Z0-9]", password):
        errors.append("Include at least one special character.")

    return errors


def hash_password(password):
    """Hash a password using scrypt and a unique random salt."""
    salt = secrets.token_bytes(SALT_LENGTH)

    derived_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LENGTH,
    )

    # Store the algorithm parameters with the salt and derived key.
    return (
        f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}"
        f"${salt.hex()}${derived_key.hex()}"
    )


def verify_password(password, stored_hash):
    """Verify a password against a stored scrypt hash."""
    try:
        algorithm, n, r, p, salt_hex, key_hex = stored_hash.split("$")

        if algorithm != "scrypt":
            return False

        n, r, p = int(n), int(r), int(p)
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)

        # Reject unreasonable parameters and malformed stored values.
        if (
            n < 2**14 or n > 2**18 or n & (n - 1)
            or not 1 <= r <= 16
            or not 1 <= p <= 4
            or len(salt) != SALT_LENGTH
            or len(expected_key) != KEY_LENGTH
        ):
            return False

        actual_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected_key),
        )

        return hmac.compare_digest(actual_key, expected_key)

    except (ValueError, TypeError, MemoryError):
        return False


def main():
    print("=" * 46)
    print("  PASSWORD POLICY AND HASHING LAB")
    print("=" * 46)

    password = getpass.getpass("Enter a test password: ")

    errors = validate_password(password)

    if errors:
        print("\nPolicy result: FAILED")
        for error in errors:
            print(f"- {error}")
        print("\nNo password hash was generated.")
        return

    print("\nPolicy result: PASSED")

    stored_hash = hash_password(password)

    print("\nGenerated password hash:")
    print(stored_hash)

    print("\nVerification test")
    candidate = getpass.getpass("Re-enter the test password: ")

    if verify_password(candidate, stored_hash):
        print("Result: Password verified successfully.")
    else:
        print("Result: Password verification failed.")

    print("\nLab completed.")


if __name__ == "__main__":
    main()
