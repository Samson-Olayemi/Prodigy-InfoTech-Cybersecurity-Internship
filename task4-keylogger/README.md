# Task 4 — Keylogger 🎹

## 📌 Description
A Python keylogger built strictly for educational and ethical use. The tool runs silently in the background, capturing every keystroke — including regular keys, special keys, and modifier keys — with millisecond-precise timestamps, and saves everything to a log file.

## 🚀 How to Run
```bash
sudo python3 keylogger.py
```
> Requires sudo for low-level keyboard access on Linux.

## ⚙️ How It Works
- Tool starts and runs completely silently — no output during capture
- Every keystroke is recorded with a timestamp in the background
- Press `ESC` to stop the keylogger
- All captured keystrokes are saved to `keylog.txt`
- Run `cat keylog.txt` to view the full log

## 🧪 Example Output (keylog.txt)
```
[2026-05-04 12:05:23,752] Key pressed: o
[2026-05-04 12:05:24,875] Special key pressed: Key.enter
[2026-05-04 12:05:29,413] Key pressed: c
[2026-05-04 12:05:30,272] Key pressed: s
[2026-05-04 12:05:57,718] Special key pressed: Key.esc
```

## 📚 What I Learned
- Keyloggers are silent by design — the victim has no idea they are being recorded
- Timestamps down to milliseconds expose the full typing pattern of a user
- Everything typed — passwords, messages, commands — is fully visible in the log
- Understanding the attack is the first step to building proper defences:
  - Endpoint Detection & Response (EDR) tools
  - Antivirus and anti-keylogger software
  - Keeping operating systems patched and updated

## 🛠️ Requirements
```bash
pip install pynput
```

## ⚠️ Disclaimer
This tool is for **educational and ethical purposes ONLY**. It was built in a controlled, supervised internship environment. Using a keylogger on any device without explicit consent of the owner is **illegal** and a serious criminal offence. Never deploy this on any system you do not own.
