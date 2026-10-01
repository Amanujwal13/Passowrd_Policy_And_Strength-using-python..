"""
Password Validator Module.
Coordinates policy application and report generation.
"""

from .policy import PasswordPolicy
from .analyzer import PasswordAnalysisResult


class PasswordValidator:
    """
    Main validator service for inspecting passwords against security policies.
    """

    def __init__(self, policy: PasswordPolicy = None):
        self.policy = policy or PasswordPolicy()

    def evaluate(self, password: str) -> PasswordAnalysisResult:
        """Evaluates a password string and returns a complete analysis result."""
        return PasswordAnalysisResult(password, self.policy)

    def print_report(self, result: PasswordAnalysisResult):
        """Displays output matching the assignment's exact terminal format."""
        if (
            result.upp_count >= 1
            and result.low_count >= 1
            and result.dig_count >= 1
            and result.spec_count >= 1
        ):
            print("All character requirements satisfied")

        if result.forbidden_found:
            print("Password should not contain forbidden words.")

        print(f"length_valid : {result.length_valid}, {'PASS' if result.length_valid else 'NOT PASS'}")
        print(f"upp_count : {result.upp_count}, {'PASS' if result.upp_count >= 1 else 'NOT PASS'}")
        print(f"low_count : {result.low_count}, {'PASS' if result.low_count >= 1 else 'NOT PASS'}")
        print(f"dig_count : {result.dig_count}, {'PASS' if result.dig_count >= 1 else 'NOT PASS'}")
        print(f"spec_count : {result.spec_count}, {'PASS' if result.spec_count >= 1 else 'NOT PASS'}")
        print(f"Forbidden found : {result.forbidden_found}, {'PASS' if not result.forbidden_found else 'NOT PASS'}")
        print(f"Password_Valid : {result.is_valid}, {'PASS' if result.is_valid else 'NOT PASS'}")
        print(f"Strength is {result.strength}!")
