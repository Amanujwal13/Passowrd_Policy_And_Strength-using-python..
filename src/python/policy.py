"""
Password Policy Definition Module.
Encapsulates configurable security constraints and institutional rules.
"""

from typing import List, Set


class PasswordPolicy:
    """
    Defines security policy rules for password validation.

    Attributes:
        min_length (int): Minimum required password length (default: 8).
        max_length (int): Maximum allowed password length (default: 14).
        special_chars (Set[str]): Set of allowed special characters.
        forbidden_words (List[str]): Lowercase list of disallowed dictionary words.
    """

    DEFAULT_FORBIDDEN = ["password", "12345", "qwerty", "admin", "username"]
    DEFAULT_SPECIAL_CHARS = "@#$%^&*!._-"

    def __init__(
        self,
        min_length: int = 8,
        max_length: int = 14,
        special_chars: str = DEFAULT_SPECIAL_CHARS,
        forbidden_words: List[str] = None,
    ):
        self.min_length = min_length
        self.max_length = max_length
        self.special_chars: Set[str] = set(special_chars)
        self.forbidden_words: List[str] = [
            word.lower() for word in (forbidden_words if forbidden_words is not None else self.DEFAULT_FORBIDDEN)
        ]

    def is_length_valid(self, length: int) -> bool:
        """Checks if a given length satisfies min and max policy constraints."""
        return self.min_length <= length <= self.max_length
