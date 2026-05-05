# Task 3 — Password Strength Assessor 🔒

## 📌 Description
A Python tool that analyzes the strength of any password and provides a detailed breakdown of exactly why it passes or fails each security criterion. It scores passwords out of 8 and returns a clear verdict — from Very Weak to Strong.

## 🚀 How to Run
```bash
python3 password_checker.py
```

## ⚙️ How It Works
The tool evaluates each password against 8 criteria:
- Minimum length (12+ characters recommended)
- Contains uppercase letters
- Contains lowercase letters
- Contains numbers
- Contains special characters
- (And additional structural checks)

It returns a score, a verdict, and a detailed breakdown of what passed and what failed.

## 🧪 Example
```
Password: 123456789
Result:   🔴 VERY WEAK — Score: 2/8
Issues:   Too short, missing uppercase, lowercase & special characters

Password: #Apostolic@58!
Result:   🟡 MODERATE — Score: 6/8
Passed:   Good length, uppercase, lowercase, numbers, special characters
```

## ⚠️ Important Limitation
This tool measures **structural complexity only**. It does NOT check if a password has been leaked or appears in known breach databases. A structurally strong password can still be compromised if it has been exposed in a data breach.

## 📚 What I Learned
- Structure does not equal safety — leaked passwords can score well structurally
- Most common passwords are dangerously weak
- Explaining *why* a password is weak drives better user behaviour than just saying it is
- Real-world password security requires breach database checks (e.g. HaveIBeenPwned API)

## 🛠️ Requirements
```
Python 3.x — no external libraries needed
```

## ⚠️ Disclaimer
For educational purposes only.
