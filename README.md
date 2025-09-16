# Password Strength Checker

A Python-based GUI tool that evaluates the strength of user-entered passwords.  
Built using **Tkinter** with color-coded progress bar, weak password detection, and a show/hide password toggle.

---
password-strength-checker/
│
├── Common_passwords.txt    # List of common weak passwords
├── LICENSE                 # License file for the project
├── README.md               # Documentation (this file)
├── password_checker.py     # Main Python script (GUI & logic)
└── requirements.txt        # Dependencies list

---

# Features
-  GUI built with Tkinter
-  Progress bar with **color feedback**
  - Red = Weak
  - Orange = Medium
  - Green = Strong
-  Detects common weak passwords from `common_passwords.txt`
-  Prevents passwords containing personal info (name, email, username)
-  Show/Hide password toggle button
-  Feedback suggestions for stronger passwords

---

# Installation & Setup
Clone the repo and run with Python 3:

```bash
git clone https://github.com/CyberRay007/password-strength-checker.git
cd password-strength-checker
pip install -r requirements.txt
python password_checker.py


