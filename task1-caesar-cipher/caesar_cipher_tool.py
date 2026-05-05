#!/usr/bin/env python3
"""
Caesar Cipher Encryption & Decryption Tool
Author: Olayemi Samson
Internship Task 1 - Cybersecurity Intern @ Prodigy InfoTech
Description: A clean, user-friendly implementation of the Caesar Cipher.
             Supports encryption and decryption with customizable shift values.
"""

def caesar_cipher(text, shift):
    """
    Encrypts or decrypts text using the Caesar Cipher algorithm.
    
    Parameters:
        text (str): The input string to process.
        shift (int): The number of positions to shift letters.
    
    Returns:
        str: The processed (encrypted or decrypted) string.
    """
    result = ""
    for char in text:
        if char.isalpha():
            # Determine the starting ASCII value based on case
            start = ord('a') if char.islower() else ord('A')
            # Calculate the shifted position
            shifted_pos = (ord(char) - start + shift) % 26
            # Convert back to character
            result += chr(start + shifted_pos)
        else:
            # Keep non-alphabetic characters unchanged
            result += char
    return result

def get_shift():
    """Prompts the user for a valid shift value and returns it."""
    while True:
        try:
            shift = int(input("Enter shift value (positive integer 1-25): "))
            if 1 <= shift <= 25:
                return shift
            else:
                print("❌ Error: Shift must be between 1 and 25.")
        except ValueError:
            print("❌ Error: Please enter a valid integer.")

def main():
    """Main function to run the Caesar Cipher tool."""
    print("""==================================================
    🔐 CAESAR CIPHER TOOL
    ==================================================
    Author: Olayemi Samson
    Internship Task 1 - Cybersecurity Intern @ Prodigy InfoTech
    """)
    
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")

        choice = input("\nEnter your choice (1/2/3): ")

        if choice == '1':
            message = input("Enter the message to encrypt: ")
            shift = get_shift()
            encrypted_message = caesar_cipher(message, shift)
            print(f"\n🔒 Encrypted Message: {encrypted_message}")
        
        elif choice == '2':
            message = input("Enter the message to decrypt: ")
            shift = get_shift()
            # To decrypt, we shift in the opposite direction
            decrypted_message = caesar_cipher(message, -shift)
            print(f"\n🔓 Decrypted Message: {decrypted_message}")

        elif choice == '3':
            print("\n👋 Thank you for using the Caesar Cipher Tool. Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
