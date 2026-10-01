"""
Command Line Interface (CLI) runner for Password Policy and Strength evaluation.
"""

from .validator import PasswordValidator


def run_cli():
    validator = PasswordValidator()

    # Prompt user for initial input
    password = input("Please Enter your password: ")

    # Re-prompt if length is outside 8 to 14, matching original assignment behavior
    while not (8 <= len(password) <= 14):
        print("Please enter password at least of length above 8 and below 14!")
        password = input("Please Enter your password: ")

    result = validator.evaluate(password)
    validator.print_report(result)


if __name__ == "__main__":
    run_cli()
