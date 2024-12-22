def xor_encrypt(input_file, output_file, key):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        key_bytes = key.encode('utf-8') 
        key_len = len(key_bytes)
        byte = f_in.read(1)
        key_index = 0
        while byte:
            f_out.write(bytes([byte[0] ^ key_bytes[key_index % key_len]]))
            byte = f_in.read(1)
            key_index += 1
xor_encrypt("disk.img", "disk_encrypted.img", "superpass")

