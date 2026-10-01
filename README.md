# 🛡️ PassShield — Password Policy & Strength Analyzer

A dual-engine project providing both an **Object-Oriented Python Security Auditor** and a modern, interactive **Web Mini-Project UI** to validate passwords against enterprise security policies and evaluate strength in real-time.

---

## 📌 Problem Statement

Develop a system that evaluates a password against institutional policies and returns:
1. **Acceptance Status (`is_valid`)**: Boolean indicating whether the password complies with all policy rules.
2. **Strength Classification**: Categorizes the password into **Strong**, **High**, **Moderate**, or **Weak**.

---

## 📋 Security Policies & Strength Rules

### 1. The 5 Institutional Policies:
1. **Length**: Must be between 8 and 14 characters (inclusive).
2. **Character Cases**: Must contain both uppercase (`A-Z`) and lowercase (`a-z`) letters (at least 1 each).
3. **Numerical Digits**: Must contain one or more numeric digits (`0-9`).
4. **Special Characters**: Must contain one or more special characters (`@, #, $, %, ^, &, *, !, ., _, -`).
5. **Forbidden Words**: Must not contain common dictionary keywords: `["password", "12345", "qwerty", "admin", "username"]`.

### 2. Strength Classification Matrix:
- 🛡️ **Strong**: Contains minimum 2 characters each (uppercase, lowercase, digits, special characters) + complies with Policy 1 & Policy 5.
- ⚡ **High**: Contains minimum 1 character each AND at least 2 characters in at least one category + complies with Policy 1 & Policy 5.
- ⚖️ **Moderate**: Contains minimum 1 character each of all four categories + complies with Policy 1 & Policy 5.
- ⚠️ **Weak**: Does not contain minimum 1 character each, OR fails Policy 1 (length) or Policy 5 (forbidden words).

---

## 📂 Project Architecture

The codebase is organized into an industry-standard, modular structure separating backend business logic, automated tests, web presentation, and documentation:

```text
Password_Policy_And_Strength/
├── docs/                                    # Project requirements & reference assets
│   ├── Password_Policy_And_Strength0.1.txt    # Original assignment prompt & policies
│   └── Screenshot 2026-09-08 150553.png     # Reference evaluation screenshot
│
├── src/
│   ├── python/                              # Core Object-Oriented Python Engine
│   │   ├── __init__.py                     # Package exports
│   │   ├── policy.py                       # PasswordPolicy entity model
│   │   ├── analyzer.py                     # PasswordAnalysisResult evaluation model
│   │   ├── validator.py                    # PasswordValidator service & reporter
│   │   └── cli.py                          # Interactive CLI prompt runner
│   │
│   └── web/                                 # Interactive Web Mini-Project Assets
│       ├── index.html                      # Standalone web app entrypoint
│       ├── css/
│       │   └── style.css                   # Glassmorphism cyber-security design system
│       └── js/
│           └── app.js                      # Real-time reactive analysis engine
│
├── tests/                                   # Automated Test Suite
│   ├── __init__.py
│   └── test_validator.py                   # 11 unit tests covering all rules & edge cases
│
├── Password_Policy_And_Strength.py          # Root entrypoint (forwards to src.python.cli)
├── .gitignore                               # Clean repo hygiene
└── README.md                                # Complete architectural documentation
```

---

## 🔍 Code Review & Improvements

During the review of the original procedural Python script, several critical bugs and structural limitations were identified and resolved:

| Area | Original Code Issue | Refactored Solution |
| :--- | :--- | :--- |
| **`Password_Valid`** | Hardcoded to `True` (`password_valid = True`), meaning it always passed even if criteria failed or forbidden words were present. | Now dynamically computed: `length_valid and upp_count >= 1 and low_count >= 1 and dig_count >= 1 and spec_count >= 1 and not forbidden_found`. |
| **Strength Logic** | Ignored Policy 1 and Policy 5 during strength calculation; an invalid password containing `"admin"` or of invalid length could be marked as "Strong" or "High". | Enforces rule: if length is invalid or forbidden words are found, strength defaults to **Weak**. |
| **OOP Architecture** | Original script was flat procedural code without classes, despite being an `OOPS ASSIGNMENT`. | Refactored into clean classes: `PasswordPolicy`, `PasswordAnalysisResult`, and `PasswordValidator` with proper encapsulation. |
| **Special Characters** | Restricted to `@#$%^&*!`; punctuation like `.` (used in README example `Gradious@123.`) was not recognized. | Expanded to include standard secure punctuation (`@#$%^&*!._-`) while remaining configurable. |
| **CLI Input Loop** | Tight `while` loop coupled validation to CLI `input()`, preventing unit testing or external integration. | Logic decoupled into pure methods (`evaluate()`, `print_report()`), while maintaining CLI compatibility. |
| **Code Hygiene** | Semicolons (`break;`), output typo (`length_vaid`), and typos in comments. | Cleaned up following PEP 8 standard conventions. |

---

## 🧪 Testing & Debugging

The project includes an automated test suite verifying every policy rule and strength tier:

### Run Automated Unit Tests:
```bash
python -m unittest discover -s tests -v
```

#### Test Suite Coverage:
- `test_assignment_readme_sample`: Verifies `Gradious@123` output matches assignment example.
- `test_strong_tier`: Verifies 2+ in all 4 categories produces `Strong`.
- `test_high_tier`: Verifies 1+ in all 4 categories and 2+ in at least one category produces `High`.
- `test_moderate_tier`: Verifies 1+ in all categories produces `Moderate`.
- `test_weak_missing_uppercase`: Catches missing uppercase characters.
- `test_weak_missing_special`: Catches missing special characters.
- `test_weak_missing_digit`: Catches missing numbers.
- `test_weak_short_length`: Catches length < 8.
- `test_weak_long_length`: Catches length > 14.
- `test_forbidden_words`: Catches `password`, `12345`, `qwerty`, `admin`, `username` regardless of case.
- `test_custom_policy`: Validates custom length ranges and custom forbidden word dictionaries.

---

## 🚀 How to Run

### Option 1: Interactive Web Mini-Project (Recommended)
You can run the web UI in two ways:

* **Directly in Browser**:
   Simply open `src/web/index.html` in any modern web browser.

* **Local HTTP Server**:
   ```bash
   python -m http.server 8080 -d src/web
   ```
   Open `http://localhost:8080` in your web browser.

#### Web Features:
- ⚡ **Real-time Live Analysis**: Immediate feedback on every keystroke.
- 👁️ **Interactive Controls**: Show/hide password toggle, clear button, copy to clipboard.
- 📊 **Dynamic 4-Segment Strength Gauge**: Visual glow and progressive light-up.
- 📋 **Live Policy Checklist**: Tracks counts (`upp_count`, `low_count`, `dig_count`, `spec_count`) and length.
- 🚨 **Forbidden Word Scanner**: Instantly highlights matched keywords (`admin`, `password`, etc.).
- 🎲 **Policy-Compliant Password Generator**: Generates 100% compliant Strong/High passwords with 1 click.
- 💻 **Python CLI Output Simulator**: Renders the exact terminal output for classroom demo and assignment grading.
- 📑 **Export Report**: Exports complete security audit summary in Markdown.

---

### Option 2: Python Terminal Program
Run the script directly from the root:

```bash
python Password_Policy_And_Strength.py
```

Or run the modular CLI package:
```bash
python -m src.python.cli
```

#### Example Output:
```text
Please Enter your password: Gradious@123
All character requirements satisfied
length_valid : True, PASS
upp_count : 1, PASS
low_count : 7, PASS
dig_count : 3, PASS
spec_count : 1, PASS
Forbidden found : False, PASS
Password_Valid : True, PASS
Strength is High!
```