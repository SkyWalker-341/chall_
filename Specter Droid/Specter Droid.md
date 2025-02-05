# **Specter Droid - Mobile Forensics CTF Challenge**

## **Category:** Mobile Forensics, Android Reverse Engineering  
## **Difficulty:** Hard  

## **Scenario**
A whistleblower has leaked a classified Android app used by a rogue intelligence agency. The app appears harmless, but analysts suspect it contains hidden messages and self-destruct mechanisms. Your mission is to **recover the hidden data**, **analyze encrypted logs**, and **reverse the app’s obfuscation** to extract the final flag.

---

## **Challenge Elements**

### **1️⃣ Extracting Suspicious Files from a Full Android Image**
- The player receives a **full Android file system dump** (from `adb backup` or `TWRP Nandroid backup`).
- The challenge requires **analyzing system logs, database files, and APKs**.
- The `/data/data/com.specter.app/` directory contains:
  - **Encrypted SQLite database** (User activity logs)
  - **Obfuscated logs with false timestamps** (Real logs hidden)

### **2️⃣ Hidden Key in System Logs and Application Logs**
- The encryption key is split across multiple log files in `/data/logs/` and `/data/system/` but **XOR-ed with a secret value**.
- Players need to **identify real logs from fake ones**, reverse the XOR operation, and reconstruct the key.

### **3️⃣ Reverse Engineering an APK**
- The leaked APK (`Specter.apk`) is **obfuscated using ProGuard**.
- The app dynamically decrypts data before displaying it.
- Players must:
  - **Decompile the APK (using JADX, Ghidra, or APKTool)**
  - **Bypass root detection**
  - **Analyze encrypted strings in the Java/Kotlin code**
  - **Find the secret decryption routine**  

### **4️⃣ Analyzing SQLite Database with Modified Entries**
- The SQLite database contains **tampered timestamps** and **misleading data**.
- Players must reconstruct the **correct timeline of events**.
- They need to recover **deleted database records** and **identify anomalies** in logins.

### **5️⃣ Steganography Inside an Image File**
- A PNG file (`classified.png`) is stored in the app’s `/sdcard/Android/data/com.specter.app/files/`.
- The image has **LSB steganography** hiding part of the final flag.
- Players must extract the **hidden data** using forensic tools.

### **6️⃣ Extracting Artifacts from Memory Dump**
- A **RAM dump (`specter_ram.img`)** from the running Android device is provided.
- Players need to analyze it using **Volatility (with Android plugins)**.
- The memory dump contains:
  - **AES decryption key**
  - **Fragments of an unencrypted message**  

### **7️⃣ Final Step: Unlocking the Flag**
- Players reconstruct the **full key** from logs, memory dump, and database.
- They use it to **decrypt a secret file (`flag.enc`)** in `/data/flag/`.

---

## **Tools Required**
- **Autopsy** / **MobSF** (Forensic analysis)
- **JADX / APKTool / Ghidra** (APK reversing)
- **DB Browser for SQLite** (Database analysis)
- **Volatility (Android Profile)** (RAM forensics)
- **StegSolve / zsteg** (Steganography)
- **CyberChef** (Data decoding)

---

## **Flag Format**
`Scr3ws4ndB0lt5{M0b1l3_F0r3ns1c_3xp3rt}`  

---

## **Why Is This Hard?**
- Requires **multiple forensic skills**: memory forensics, log analysis, and database recovery.
- Needs **APK reverse engineering and bypassing protections**.
- Uses **steganography and obfuscation** to hide key artifacts.
- Includes **fake forensic leads** to mislead players.

---

## **Next Steps**
- **Do you want sample files for this challenge?**
- **Need guidance on setting up the environment?**

Let me know how I can assist! 🚀

