# **SSH Challenge: Shadow Key**

## **Overview**
This challenge presents a unique and difficult SSH-based CTF scenario. The goal is to bypass multiple layers of deception, restricted shells, hidden services, and privilege escalation mechanisms to retrieve the final flag.

---

## **Scenario**
You gain SSH access but face multiple obstacles before reaching the flag:
1. A **restricted shell (rbash)** that limits commands.
2. A **hidden secondary SSH service** running on an **uncommon port**.
3. An **obfuscated private SSH key** that requires decryption.
4. **Privilege escalation challenges** involving environment variables.
5. A **fake flag** to mislead the attacker.
6. The **real flag is stored in memory** and requires dumping a process.

---

## **Challenge Steps**
### **Step 1: Initial SSH Login (Restricted Shell)**
- The user logs in to SSH but finds themselves in `rbash` (restricted shell).
- Commands like `cd`, `ls`, and `cat` are disabled.
- Limited commands such as `echo`, `grep`, or a misleading `help` script are available.
- The user must **escape rbash** (e.g., via environmental variable manipulation or exploiting a misconfigured command).

### **Step 2: Finding the Secondary SSH Service**
- SSH is running on **port 2222**, but it’s hidden from normal users.
- Clues about this port exist in:
  - A hidden cron job
  - A `systemd` service file
  - Network logs in `/var/log/auth.log` (or similar location)
- The attacker must find the correct port and re-login.

### **Step 3: Unlocking the Private SSH Key**
- A **private SSH key** exists but is encrypted.
- It is hidden in an unexpected location, such as:
  - `.bash_history`
  - A log file (`/var/log/ssh_debug.log`)
  - Embedded in an image (steganography)
- The attacker must decrypt the key using a **custom obfuscation algorithm** found in a Python or Bash script.

### **Step 4: Privilege Escalation via Environment Variables**
- The attacker lands in another restricted shell upon logging into the secondary SSH.
- `sudo` access is blocked.
- The system is vulnerable to **LD_PRELOAD**, **PATH hijacking**, or **capabilities abuse**.
- Exploiting one of these mechanisms grants root access.

### **Step 5: Avoiding the Fake Flag**
- A fake flag exists in `/home/user/flag.txt` to mislead the attacker.
- The real flag is stored **in memory**.
- Retrieving it requires:
  - Dumping a process (`gcore`, `strings /proc/<pid>/mem`)
  - Extracting an SSH agent’s socket secret.

---

## **Additional Twists to Make It Harder**
1. **SSH Honeypot**: A fake SSH login that logs every command the attacker types.
2. **iptables Firewall Trick**: The system allows only **one SSH connection per IP** before blocking further attempts.
3. **Unstable Connection**: A cron job restarts SSH every 2 minutes to force time pressure.
4. **Custom Encrypted Bash History**: `.bash_history` is encrypted with a simple ROT cipher.
5. **Log Manipulation**: System logs are tampered with, requiring reconstruction.

---

## **Flag Retrieval**
- The real flag is stored in **a memory dump** or **a hardcoded binary**.
- It may also require **reconstructing SSH session logs** (`utmp`, `wtmp`).
- Alternatively, it could be extracted from **a hidden SSH agent socket**.

---

## **Deployment Instructions**
- Set up an **Ubuntu/Debian-based VM**.
- Configure `rbash` as the default shell for a low-privileged user.
- Create a **fake flag** in `/home/user/flag.txt`.
- Hide the **real flag** in memory or require dumping a process.
- Configure SSH on **port 2222** and obscure its presence.
- Implement **privilege escalation mechanisms** using environmental variables or misconfigurations.
- Modify logs to include misleading entries.

---

## **Conclusion**
This challenge is designed to test **OSINT, privilege escalation, SSH enumeration, steganography, and forensic skills**. Players must think outside the box to break out of restrictions, pivot between users, and retrieve the flag.

Good luck!

