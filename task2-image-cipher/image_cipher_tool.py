#!/usr/bin/env python3

"""
Image Encryption Tool (Pixel Manipulation)
Author: Olayemi Samson
Internship Task 2 - Cybersecurity Intern @ Prodigy InfoTech
Description: Encrypts and decrypts images by manipulating pixel values using XOR.
             This version forces RGB mode to ensure perfect decryption back to original.
"""

from PIL import Image


def print_header():
    print("=" * 80)
    print("🖼️  IMAGE ENCRYPTION TOOL (PIXEL MANIPULATION)")
    print("Author: Olayemi Samson")
    print("Internship Task 2 - Cybersecurity Intern @ Prodigy InfoTech")
    print("=" * 80)
    print("Encrypts/decrypts images using XOR pixel cipher.\n")


def encrypt_decrypt_image(input_path, output_path, key, mode="encrypt"):
    try:
        img = Image.open(input_path).convert("RGB")   # Force RGB mode - This fixes the problem
        pixels = img.load()
        width, height = img.size
        action = "Encrypted" if mode == "encrypt" else "Decrypted"

        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                r = (r ^ key) % 256
                g = (g ^ key) % 256
                b = (b ^ key) % 256
                pixels[x, y] = (r, g, b)

        img.save(output_path)
        print(f"✅ {action} successfully!")
        print(f"   Input  → {input_path}")
        print(f"   Output → {output_path}\n")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    print_header()
    
    while True:
        print("1. Encrypt an image")
        print("2. Decrypt an image")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1/2/3): ").strip()
        
        if choice == "3":
            print("👋 Thank you for using the Image Encryption Tool. Goodbye!\n")
            break
        elif choice in ["1", "2"]:
            input_path = input("Enter input image path: ").strip()
            output_path = input("Enter output image path: ").strip()
            
            try:
                key = int(input("Enter key (0-255): "))
            except ValueError:
                print("❌ Please enter a valid number.\n")
                continue
                
            mode = "encrypt" if choice == "1" else "decrypt"
            encrypt_decrypt_image(input_path, output_path, key, mode)
        else:
            print("❌ Invalid choice. Please select 1, 2, or 3.\n")


if __name__ == "__main__":
    main()
