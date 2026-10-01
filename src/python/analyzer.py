"""
Password Analysis Result Module.
Encapsulates character frequency counting, policy compliance, and strength calculation.
"""

from typing import List, Set
from .policy import PasswordPolicy


class PasswordAnalysisResult:
    """
    Encapsulates the character composition and validation verdict of a password.
    """

    def __init__(self, password: str, policy: PasswordPolicy):
        self.password = password
        self.length = len(password)
        self.length_valid = policy.is_length_valid(self.length)

        self.upp_count = 0
        self.low_count = 0
        self.dig_count = 0
        self.spec_count = 0
        self._count_characters(policy.special_chars)

        self.matched_forbidden = self._find_forbidden_words(policy.forbidden_words)
        self.forbidden_found = len(self.matched_forbidden) > 0

        # Policy validity: All 5 rules must be satisfied
        self.is_valid = (
            self.length_valid
            and self.upp_count >= 1
            and self.low_count >= 1
            and self.dig_count >= 1
            and self.spec_count >= 1
            and not self.forbidden_found
        )

        self.strength = self._calculate_strength()

    def _count_characters(self, special_chars: Set[str]):
        """Counts character occurrences across uppercase, lowercase, digits, and special characters."""
        for char in self.password:
            if char.isupper():
                self.upp_count += 1
            elif char.islower():
                self.low_count += 1
            elif char.isdigit():
                self.dig_count += 1
            elif char in special_chars:
                self.spec_count += 1

    def _find_forbidden_words(self, forbidden_words: List[str]) -> List[str]:
        """Scans the password for forbidden dictionary substrings."""
        lowered = self.password.lower()
        return [word for word in forbidden_words if word in lowered]

    def _calculate_strength(self) -> str:
        """
        Determines the strength classification per the assignment specifications:
        - Weak: Fails length (8-14), or contains forbidden words, or lacks >=1 in any category.
        - Strong: Contains min 2 characters each (Upper, Lower, Digit, Special) + Policy compliant.
        - High: Contains min 1 character each AND at least 2 in at least one category + Policy compliant.
        - Moderate: Contains min 1 character each of all four categories + Policy compliant.
        """
        if not self.length_valid or self.forbidden_found:
            return "Weak"

        has_min_1 = (
            self.upp_count >= 1
            and self.low_count >= 1
            and self.dig_count >= 1
            and self.spec_count >= 1
        )

        if not has_min_1:
            return "Weak"

        has_all_2 = (
            self.upp_count >= 2
            and self.low_count >= 2
            and self.dig_count >= 2
            and self.spec_count >= 2
        )

        if has_all_2:
            return "Strong"

        has_any_2 = (
            self.upp_count >= 2
            or self.low_count >= 2
            or self.dig_count >= 2
            or self.spec_count >= 2
        )

        if has_any_2:
            return "High"

        return "Moderate"
