import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Base64-encoded encryption key
ENCRYPTION_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
KEY = base64.b64decode(ENCRYPTION_KEY)

# AES block size
BLOCK_SIZE = 16

def decrypt_file(file_path, key):
    # Read the encrypted file content
    with open(file_path, 'rb') as f:
        # The first 16 bytes are the IV (Initialization Vector)
        iv = f.read(BLOCK_SIZE)
        ciphertext = f.read()

    # Initialize AES cipher in CBC mode with the extracted IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    # Write the decrypted data back to the file
    with open(file_path, 'wb') as f:
        f.write(plaintext)

def decrypt_folder(folder_path, key):
    # Walk through the directory and decrypt each file
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"Decrypting: {file_path}")
            decrypt_file(file_path, key)

if __name__ == "__main__":
    # Specify the folder to decrypt
    folder_to_decrypt = input("Enter the path of the folder to decrypt: ")

    if os.path.exists(folder_to_decrypt):
        print(f"Starting decryption of folder: {folder_to_decrypt}")
        decrypt_folder(folder_to_decrypt, KEY)
        print("Decryption completed.")
    else:
        print("The specified folder does not exist.")