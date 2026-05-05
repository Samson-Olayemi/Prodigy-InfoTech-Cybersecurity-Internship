# Task 2 — Image Encryption Tool 🖼️🔐

## 📌 Description
A Python tool that encrypts and decrypts image files using XOR pixel manipulation. Every pixel in the image is XOR-ed with a secret key, transforming the image into an unrecognizable, distorted output. Applying the same key again perfectly restores the original — demonstrating symmetric encryption at the pixel level.

## 🚀 How to Run
```bash
python3 image_cipher_tool.py
```

## ⚙️ How It Works
- User selects Encrypt or Decrypt from the menu
- Provides input image path, output image path, and a key (0–255)
- The tool reads every pixel and applies XOR with the key
- Since XOR is self-reversing, the same key both encrypts and decrypts

## 🧪 Example
```
Option:  1 (Encrypt)
Input:   original.png
Output:  encrypted.png
Key:     42
→ Image becomes completely distorted and unrecognizable

Option:  2 (Decrypt)
Input:   encrypted.png
Output:  decrypted.png
Key:     42
→ Image is restored pixel-for-pixel to the original
```

## 📚 What I Learned
- How XOR cipher works at the binary/pixel level
- Why symmetric encryption depends entirely on key secrecy
- The critical importance of key management — lose the key, lose the data
- How data is just numbers, and security is about how well you scramble them

## 🛠️ Requirements
```bash
pip install pillow
```

## ⚠️ Disclaimer
For educational purposes only.
