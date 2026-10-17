
# Password Policy and Hashing Lab

A Python-based cybersecurity lab demonstrating password policy
validation, secure password hashing, and password verification.

## Objectives

- Enforce a basic password complexity policy.
- Hash passwords using Python's scrypt implementation.
- Generate a unique random salt for each password hash.
- Verify passwords without storing plaintext credentials.
- Test correct, incorrect, and malformed password hashes.

## Technologies

- Python 3
- hashlib
- secrets
- hmac
- unittest

## Password Policy

The lab checks for:

- Minimum length of 12 characters
- At least one lowercase letter
- At least one uppercase letter
- At least one number
- At least one special character

These are the rules used in this educational exercise, not a
universal security standard.

## How It Works

1. The user enters a test password through hidden terminal input.
2. The program checks the password policy.
3. A valid password is hashed using scrypt with a random salt.
4. The program verifies a second password against the hash.
5. The result is displayed without saving the plaintext password.

## Run the Lab

```bash
python password_lab.py
```

On Windows, you can also use:

```bash
py password_lab.py
```

## Run Tests

```bash
python -m unittest -v
```

## Security Notes

- Use only fictional test passwords.
- Do not enter personal or reused passwords.
- This project does not save credentials to a file or database.
- Password hashing is different from encryption: hashes are not
  intended to be decrypted.
- This is an educational project, not a production login system.

## Learning Outcome

This project demonstrates basic defensive security concepts
related to password policies, salted password hashing, and
credential verification.

## Disclaimer

Created for educational and defensive cybersecurity learning.
