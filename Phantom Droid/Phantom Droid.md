# Phantom Droid Challenge

## Challenge Overview
An Android application was installed on a test device. The app encrypted user data, reset the device password, and then deleted itself from the system.

However, traces of the app remain in system logs, backup files, and residual stored data. Your task is to recover the app, analyze its behavior, and decrypt the data to retrieve the flag.

## Challenge Objectives
- Recover the deleted application
- Analyze system logs for traces of app activity
- Identify the encryption method and retrieve the key
- Decrypt the data and find the flag

## Difficulty Level
🔴 **Hard**

## Challenge Setup & Implementation
### 1. **Application Behavior**
- The app encrypts user data upon execution.
- It resets the device password.
- It self-deletes after execution, making it harder to analyze.

### 2. **Forensic Clues & Implemented Complexity**
- **Encryption Key Hiding**
  - The encryption key is **XORed with a hidden value**.
  - Key fragments are stored in **multiple locations** (system logs, backup files, SQLite database).
- **System Log Manipulation**
  - Timestamps are **randomized**.
  - Fake log entries are injected to mislead forensic analysis.
- **App Self-Deletion**
  - Instead of normal uninstallation, the app **overwrites itself with a junk file**.
  - Selective wiping of log data is performed to hide traces.

## Expected Artifacts
- **System Logs** (`/data/system/logs/` or `/var/logs/`)
- **Backup Data** (`/sdcard/Android/data/com.example.app/backup/`)
- **SQLite Database** (Encrypted key storage)

## Required Forensic Techniques
- **Log Analysis**: Find modified timestamps and injected fake logs.
- **File Recovery**: Extract app backup files and analyze them.
- **Reverse Engineering**: Decompile the app (if recovered) and analyze its encryption logic.
- **Cryptanalysis**: Decode the key storage and decrypt the user data.

## Suggested Tools
| Tool       | Purpose |
|------------|--------------------------------------------------------|
| **ADB**    | Analyze logs, retrieve files from Android device. |
| **Autopsy** | File carving and forensic analysis. |
| **JADX** / **Ghidra** | Decompile and reverse-engineer APKs. |
| **Frida**  | Perform runtime analysis on an extracted APK. |

## Steps to Solve
1. Extract system logs and find **traces of the deleted app**.
2. Identify and recover **backup files** containing fragments of the encryption key.
3. Analyze the SQLite database for **hidden key components**.
4. Reverse-engineer the encryption algorithm from the recovered app (if found).
5. Decrypt the data and retrieve the final **flag**.

## Flag Format
```
Scr3ws4ndB0lt5{h@PpY_4ndR0Id}
```


