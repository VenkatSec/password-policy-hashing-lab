
import unittest

from password_lab import (
    validate_password,
    hash_password,
    verify_password,
)


class PasswordLabTests(unittest.TestCase):

    def test_strong_password_passes_policy(self):
        self.assertEqual(validate_password("BlueTeam!2026Lab"), [])

    def test_short_password_fails_policy(self):
        self.assertTrue(validate_password("Ab1!short"))

    def test_hash_does_not_equal_plaintext(self):
        password = "BlueTeam!2026Lab"
        stored_hash = hash_password(password)
        self.assertNotEqual(stored_hash, password)

    def test_correct_password_verifies(self):
        password = "BlueTeam!2026Lab"
        stored_hash = hash_password(password)
        self.assertTrue(verify_password(password, stored_hash))

    def test_incorrect_password_fails(self):
        stored_hash = hash_password("BlueTeam!2026Lab")
        self.assertFalse(verify_password("WrongPassword!2026", stored_hash))

    def test_each_hash_uses_a_unique_salt(self):
        password = "BlueTeam!2026Lab"
        self.assertNotEqual(
            hash_password(password),
            hash_password(password),
        )

    def test_malformed_hash_fails_safely(self):
        self.assertFalse(verify_password("anything", "not-a-valid-hash"))


if __name__ == "__main__":
    unittest.main()
