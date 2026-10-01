"""
Password Policy and Strength Checker
Entry point for assignment submission & execution.
Delegates to modular OOP package in src.python.
"""

import sys
import os

# Ensure src is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.python.policy import PasswordPolicy
from src.python.analyzer import PasswordAnalysisResult
from src.python.validator import PasswordValidator
from src.python.cli import run_cli

if __name__ == "__main__":
    run_cli()