# Task 1 — Caesar Cipher Tool 🔑

## 📌 Description
A Python implementation of the classic Caesar Cipher — one of the oldest known encryption techniques. The tool encrypts and decrypts text messages by shifting each letter in the alphabet by a user-defined key.

## 🚀 How to Run
```bash
python3 caesar_cipher.py
```

## ⚙️ How It Works
- The user enters a plaintext message and a shift key (number)
- Each letter is shifted forward by the key value for encryption
- The same key shifts letters backward for decryption
- Numbers, spaces, and punctuation are left unchanged

## 🧪 Example
```
Input:  "Cybersecurity is not just a skill"
Key:     3
Output: "Fbeuvfhxulwb lv qrw mxvw d vnloo"

Decrypt with key 3 → restores original message perfectly
```

## 📚 What I Learned
- How classical substitution ciphers work
- Why algorithm secrecy is not enough — only 25 possible keys makes brute-force trivial
- The importance of handling edge cases (uppercase, lowercase, punctuation)
- Foundation of why modern encryption relies on strong, secret keys — not secret methods

## 🛠️ Requirements
```
Python 3.x — no external libraries needed
```

## ⚠️ Disclaimer
For educational purposes only.
