import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Base64-encoded encryption key
ENCRYPTION_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
KEY = base64.b64decode(ENCRYPTION_KEY)

# AES block size
BLOCK_SIZE = 16

def encrypt_file(file_path, key):
    # Read the file content
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Initialize AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    
    # Encrypt and pad the data
    ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))

    # Write the encrypted data back to the file
    with open(file_path, 'wb') as f:
        # Write IV (Initialization Vector) first
        f.write(cipher.iv)
        # Then write the encrypted data
        f.write(ciphertext)

def encrypt_folder(folder_path, key):
    # Walk through the directory and encrypt each file
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"Encrypting: {file_path}")
            encrypt_file(file_path, key)

if __name__ == "__main__":
    # Specify the folder to encrypt
    folder_to_encrypt = input("Enter the path of the folder to encrypt: ")

    if os.path.exists(folder_to_encrypt):
        print(f"Starting encryption of folder: {folder_to_encrypt}")
        encrypt_folder(folder_to_encrypt, KEY)
        print("Encryption completed.")
    else:
        print("The specified folder does not exist.")