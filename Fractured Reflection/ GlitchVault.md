# Challenge:  GlitchVault

## Description 

The pieces are there, but not where they belong. Patterns have been disrupted, sequences altered, and what should be clear is obscured by manipulation. Shift your perspective, restore the broken order, and uncover what was meant to be seen.

## Challenge Details

1. **Cracking the ZIP Password**  
   We have a ZIP file named `challegen.zip` that is password protected. Since the password is unknown, use a brute-force approach with the `rockyou.txt` wordlist. Tools like fcracker or John the Ripper can be utilized to recover the password.

2. **Extracting the Files**  
   After cracking the password and extracting the contents, you will find the following files:
   - A `pacapng` file
   - An ELF file
   - An `sslkey.log` file

![Screenshot from 2025-03-08 17-23-12](https://github.com/user-attachments/assets/fffaaa58-68dd-49ba-a62a-28f70805a88a)

  **decryption script***
    ```

    import base64
    std_b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    custom_map = {ch: ch for ch in std_b64_alphabet}
    custom_map['='] = '/'  
    custom_map['a'] = '#'
    custom_map['G'] = '%'
    custom_map['V'] = '&'
    custom_map['s'] = '*'
    custom_map['b'] = '@'
    custom_map['8'] = '<'
    
    reverse_map = {v: k for k, v in custom_map.items()}
    
    def custom_decode(encrypted_message):
        standard_encoded = ''.join(reverse_map.get(ch, ch) for ch in encrypted_message)
        decoded_message = base64.b64decode(standard_encoded).decode()
        return decoded_message

    encrypted_file_path = "_Sslkey.log"
    
    def decrypt_file(input_file):
        with open(input_file, "r") as f:
            encrypted_content = f.read()
        decrypted_content = custom_decode(encrypted_content)
        return decrypted_content
    decrypted_content = decrypt_file(encrypted_file_path)
    print(decrypted_content)
    
    ```
![Screenshot from 2025-03-08 18-29-20](https://github.com/user-attachments/assets/f3d4317c-a93c-4067-9006-4448f41def0b)


3. **Decrypting the SSL Key Log**  
   The `sslkey.log` file is encrypted. To decode it, perform the following steps:
   - **ELF Analysis:** Use an ELF analyzer such as IDA or Ghidra to extract the decryption program from the ELF file. Then, use this program to decode the `sslkey.log` file.
   - **Wireshark Decryption:** Apply the SSL key decoder in Wireshark on the TLS packets. Once decrypted, you will observe HTTP content that contains an `.apk` file.  
     Export the APK file using Wireshark by navigating to **File → Export Objects → HTTP**, then select the APK file and save it.


![image](https://github.com/user-attachments/assets/eeb038a2-0c4d-45e2-8f9c-b7b963f4de8b)
---

**apk alyzer**

---

4. **Analyzing the APK File**  
   Within the APK file, you will find a file named `flag.png`.  
   The PNG image appears to have its chunks in reverse or incorrect order:
   - The image is upside-down because the PNG end chunk (`IEND`), which signifies the end of the file, appears at the start.
![Screenshot from 2025-03-08 18-30-46](https://github.com/user-attachments/assets/1cbc2207-e24a-4c3a-9cde-8a1ee899842f)

   - To correct this, first flip the image upside-down.
   - Then, reverse the order of every 8-bit chunk to restore the proper structure.
     
## script:
```
with open("reverse_flag", "rb") as f:
    encrypted_data = f.read()


chunk_size = 8


chunks = [encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size)]


original_chunks = [chunk[::-1] for chunk in chunks]


with open("flag.png", "wb") as f:
    for chunk in original_chunks:
        f.write(chunk) 

```
   - Finally, convert the hexadecimal data into raw binary data.

![Screenshot from 2025-03-07 20-22-59](https://github.com/user-attachments/assets/64c359c8-c2f6-4c00-89db-f3f508bb4fc8)

The resulting image will reveal the flag.

### Flag : P3nt35t{M0b1l3_F0r3ns1c_3xp3rt}
