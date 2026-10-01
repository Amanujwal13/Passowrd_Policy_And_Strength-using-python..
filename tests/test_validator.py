"""
Automated Test Suite for Password Policy & Strength Checker.
Runs with Python's built-in unittest framework.
"""

import unittest
from src.python.policy import PasswordPolicy
from src.python.validator import PasswordValidator


class TestPasswordValidator(unittest.TestCase):

    def setUp(self):
        self.validator = PasswordValidator()

    def test_assignment_readme_sample(self):
        """Test default example from assignment README: Gradious@123"""
        result = self.validator.evaluate("Gradious@123")
        self.assertTrue(result.length_valid)
        self.assertEqual(result.upp_count, 1)
        self.assertEqual(result.low_count, 7)
        self.assertEqual(result.dig_count, 3)
        self.assertEqual(result.spec_count, 1)
        self.assertFalse(result.forbidden_found)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.strength, "High")

    def test_strong_tier(self):
        """Test Strong tier: min 2 characters in all four categories"""
        result = self.validator.evaluate("Ab#1Cd$2")
        self.assertTrue(result.is_valid)
        self.assertGreaterEqual(result.upp_count, 2)
        self.assertGreaterEqual(result.low_count, 2)
        self.assertGreaterEqual(result.dig_count, 2)
        self.assertGreaterEqual(result.spec_count, 2)
        self.assertEqual(result.strength, "Strong")

    def test_high_tier(self):
        """Test High tier: min 1 in all categories, at least 2 in one category"""
        # Uppercase has 2, others have 1
        result = self.validator.evaluate("ABcd12!#")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.strength, "Strong")  # all have 2

        # Exactly 1 in upper, spec; 2 in low, dig
        result2 = self.validator.evaluate("A!bb22zz")
        self.assertTrue(result2.is_valid)
        self.assertEqual(result2.strength, "High")

    def test_moderate_tier(self):
        """Test Moderate tier: min 1 character each of upper, lower, digit, special (none have 2+)"""
        # 4 chars: 1 upper, 1 lower, 1 digit, 1 special. Total length 8, so other 4 must not repeat any category?
        # Wait, if total length is 8, pigeonhole principle means at least one category will have 2 or more characters!
        # Let's verify: 8 chars divided into 4 categories -> ceil(8/4) = 2.
        # So ANY valid password of length 8 to 14 will naturally have at least 2 in one category!
        # Therefore, any valid password meeting 1 each of all 4 categories will be at least "High" or "Strong"!
        # But if someone configured min_length: 4, e.g. "A1b@" -> length 4, 1 each:
        custom_policy = PasswordPolicy(min_length=4, max_length=14)
        custom_validator = PasswordValidator(custom_policy)
        res_mod = custom_validator.evaluate("A1b@")
        self.assertTrue(res_mod.is_valid)
        self.assertEqual(res_mod.strength, "Moderate")

    def test_weak_missing_uppercase(self):
        """Test Weak tier: missing uppercase character"""
        result = self.validator.evaluate("gradious@123")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.upp_count, 0)
        self.assertEqual(result.strength, "Weak")

    def test_weak_missing_special(self):
        """Test Weak tier: missing special character"""
        result = self.validator.evaluate("Gradious1234")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.spec_count, 0)
        self.assertEqual(result.strength, "Weak")

    def test_weak_missing_digit(self):
        """Test Weak tier: missing digit"""
        result = self.validator.evaluate("Gradious@XYZ")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.dig_count, 0)
        self.assertEqual(result.strength, "Weak")

    def test_weak_short_length(self):
        """Test Weak tier: length < 8"""
        result = self.validator.evaluate("Ab1@")
        self.assertFalse(result.length_valid)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.strength, "Weak")

    def test_weak_long_length(self):
        """Test Weak tier: length > 14"""
        result = self.validator.evaluate("Abcd1234!@#$VeryLong")
        self.assertFalse(result.length_valid)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.strength, "Weak")

    def test_forbidden_words(self):
        """Test Policy 5: forbidden words must be flagged and invalidate password"""
        forbidden_test_cases = [
            ("admin1234@A", "admin"),
            ("Password@123", "password"),
            ("Qwerty@1234", "qwerty"),
            ("12345Abcdef!", "12345"),
            ("UsernamE@123", "username"),
        ]
        for pwd, expected_word in forbidden_test_cases:
            with self.subTest(password=pwd, word=expected_word):
                result = self.validator.evaluate(pwd)
                self.assertTrue(result.forbidden_found)
                self.assertIn(expected_word, result.matched_forbidden)
                self.assertFalse(result.is_valid)
                self.assertEqual(result.strength, "Weak")

    def test_custom_policy(self):
        """Test custom policy configuration"""
        custom_policy = PasswordPolicy(
            min_length=10,
            max_length=20,
            forbidden_words=["secret", "gradious"]
        )
        custom_validator = PasswordValidator(custom_policy)

        # Gradious is now forbidden
        res = custom_validator.evaluate("Gradious@123")
        self.assertTrue(res.forbidden_found)
        self.assertFalse(res.is_valid)


if __name__ == "__main__":
    unittest.main()
