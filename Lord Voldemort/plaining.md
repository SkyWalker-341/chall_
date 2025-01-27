# Malware Challenge Plan

### Objective
To create a challenge where opening a malicious image file triggers ransomware-like behavior. The malware will:

1. Encrypt all files except:
   - `boot`
   - `shell-config`
   - `proc-config`
   - `keyfile`
   - The malware script itself

2. Sabotage mechanism:
   - Create a process that hides the key file.
   - The key file remains hidden until the user kills the process, at which point the key file becomes accessible.

3. After encrypting the files and hiding the key file:
   - Reverse the script content (e.g., "hello" becomes "olleh").
   - Randomly rearrange the characters and provide an index mapping (e.g., "olleh" becomes "lhoel-f{1,3,0,4,2}").
   - Encrypt the malware script itself using Base64.

4. Create a `.flag.txt` file in `/tmp`.

---

### NOTE
-> use sysmetic key cipher the key must  genrated by cipher and stored key in key file 
-
