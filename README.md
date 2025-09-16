# Password Strength Checker

A Python-based GUI application built with CustomTkinter that helps users create strong and secure passwords.
The tool checks password strength based on length, complexity, uniqueness, and a built-in weak password bank, while also ensuring the password doesn’t contain personal information (like name, email, or username).

 # Features

Modern GUI built with CustomTkinter (dark theme enabled).

User enters Name, Email, Username, and Password directly in the app.

Validates inputs (ensures all fields filled, checks valid email format).

Analyzes password for:

Minimum length (8+)

Strong length (12+)

Uppercase & lowercase letters

Numbers

Special characters (@, $, !, %, *, ?, &)

Checks against a built-in bank of 70+ common weak passwords.

Ensures password does not contain user’s personal info.

Provides feedback & suggestions for improvement.

Visual progress bar for password strength (Weak, Medium, Strong).

Show/Hide password toggle.

Alerts when password is strong .

# Project Structure
password-strength-checker/
│
├── password_checker.py      
├── README.md                 
└── LICENSE
└── requirements.txt

(Example with Name, Email, Username, Password fields)


Password Strength Feedback

# Installation & Usage

Clone the repository:

git clone https://github.com/cyberray007/password-strength-checker.git
cd password-strength-checker


# Install dependencies:

pip install customtkinter


Run the program:

python password_checker.py


Enter your Name, Email, Username, and Password in the GUI window.

Click Check Strength → see feedback, suggestions, and strength meter.

# Future Improvements

Add real-time validation (disable button until inputs are valid).

Implement a password generator (auto-create secure random passwords).

Add copy-to-clipboard button for generated/entered passwords.

Provide a dark/light mode toggle for the GUI.

Store past checks securely for analysis (optional).