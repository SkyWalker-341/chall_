# Rise of Ultron (Revised Challenge Plan)

## Overview

This challenge consists of multiple levels, each utilizing a different networking protocol or concept. Participants will progress through the levels by analyzing network data and solving puzzles embedded in traffic captures or system interactions.

## Revised Challenge Plan

### Level 1: ICMP (Ping Protocol)

- **Task:** The hidden flag is embedded within a series of IP addresses sent via ICMP packets.
- **Hint:** The IP addresses contain noise (extra numerical values). Participants must filter and decode these values to reveal the flag.

### Level 2: HTTP Protocol

- **Task:** The flag is hidden as a username within a URL. However, the URL is encoded using a JavaScript obfuscation script.
- **Hint:** Participants must reverse-engineer the obfuscated JavaScript code to extract the hidden username.

### Level 3: DNS Protocol

- **Task:** The flag describes the attack technique used to compromise the system.
- **Hint:** The DNS header contains ASCII values representing the flag. These values must be extracted and base64-decoded to obtain the final text.

### Level 4: Encrypted TCP

- **Task:** This level contains **half** of the final password.
- **Hint:** Participants must reverse an ELF binary to obtain the decryption key, then use it to decrypt the TCP traffic. The traffic contains the first half of the password.

### Final Level: SSH Access & Root Flag

- **Step 1:** Combine the first four flags (ICMP, HTTP, DNS, Encrypted TCP).
- **Step 2:** Rearrange them randomly and generate a SHA-256 hash.
- **Step 3:** Use the following credentials to initiate an SSH connection:
  - **Username:** Extracted from Level 2 (HTTP)
  - **Password:** Derived SHA-256 hash
  - **IP Address:** Extracted from Level 1 (ICMP)

#### Objective:
- SSH into the system using the credentials.
- The final flag is stored in `flag.txt`, accessible only by the `root` user.

### Additional Challenge: Flask Application Access

- **Complication:** The Flask application that reads the `flag.txt` file belongs to a different user group.
- **Steps:**
  1. Use private keys found in the system to log in as other users.
  2. Modify user groups to grant the original user access to the Flask application's group.
  3. Analyze the Flask code for vulnerabilities (e.g., improper validation).
  4. Exploit the application to read `flag.txt` and retrieve the **final root flag**.

---

