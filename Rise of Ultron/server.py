import socket

# Server setup
IP = '127.0.0.1'
PORT = 9090

# Level data
levels = {
    1: {"username": "Black Widow", "password": "1'vE_go7_R3D_in_my_LeDgER", 
        "description": "Black Widow left a coded message in the echoes of the network. Find the hidden payload she sent to uncover her password.\nHint: Think of network pings and packet analysis."},
    2: {"username": "Falcon", "password": "N0_$upER_seruM_nO_B10ND_hA!r", 
        "description": "Falcon's flight records were intercepted during a file transfer session. Analyze the captured exchange to retrieve his password."},
    3: {"username": "War Machine", "password": "RE41_W4r_Is_Fought_F4Ce_To_fAC3", 
        "description": "War Machine’s password is hidden in a web conversation. Investigate the requests and responses to extract his credentials."},
    4: {"username": "Hulk", "password": "a1w4Y$_4NgrY", 
        "description": "Hulk sent a message, but Ultron intercepted it in transit. Study the contents of the recovered mail to find his password."},
    5: {"username": "Thor", "password": "P0!Nt_BR3@K", 
        "description": "Thor’s password is hidden in a mysterious query to a naming server. Decode the request to retrieve his credentials."},
    6: {"username": "Captain America", "password": "57op_PRETeNdIn9_tO_83_A_h3RO", 
        "description": "Ultron encrypted Captain America's plans with a strong cipher and sent them over a secure channel. Decrypt the data stream to uncover his password.\nHint: Look for encrypted traffic and use symmetric decryption."},
    7: {"username": "Iron Man", "password": "!_4m_!r0N_mAn", 
        "description": "Iron Man’s armor systems are locked, and the key is stored within a file-sharing session. Crack the encoded challenge to power up his suit."},
    8: {"username": "Watcher", "password": "84c61f0a7d7b853504dee4d1802710574c4f107f6c7cedfea59d2bb652745ef9", 
        "description": "The Watcher has seen all. Combine the knowledge of your previous victories, hash the correct combination of secrets, and unlock his domain."}
}

# Start the server
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((IP, PORT))
        server.listen()
        print(f"Server running on {IP}:{PORT}")

        while True:
            conn, addr = server.accept()
            with conn:
                print(f"Connection established with {addr}")
                conn.sendall(b"Welcome to the Ultron Challenge Server!\n")
                conn.sendall(b"Description: Ultron has launched a cyberattack on your system, deleting all user passwords and encrypting them.\n")
                conn.sendall(b"Fortunately, we recovered a network packet capture (pcap) file containing the encrypted passwords.\n")
                conn.sendall(b"Your mission is to analyze the pcap file, decipher the passwords for each user, and help us restore the system before it's too late!\n\n")

                current_level = 1
                attempts = 0
                max_attempts = 3

                while current_level <= 7:
                    level_data = levels[current_level]
                    conn.sendall(f"Level {current_level}:\nDescription: {level_data['description']}\nLogin: {level_data['username']}\n".encode())

                    # Password attempt loop
                    while attempts < max_attempts:
                        conn.sendall(b"Enter password: ")
                        password = conn.recv(1024).decode().strip()

                        if password == level_data["password"]:
                            conn.sendall(f"Password correct! You may proceed to the next level.\n".encode())
                            current_level += 1
                            attempts = 0  # Reset attempt counter for the next level
                            break
                        else:
                            attempts += 1
                            conn.sendall(f"Incorrect password. You have {max_attempts - attempts} attempt(s) left.\n".encode())
                    
                    if attempts == max_attempts:
                        conn.sendall(b"Too many incorrect attempts. Exiting the challenge.\n")
                        break

                # After Level 7 (Iron Man), give the player the first part of the flag
                if current_level == 8:
                    conn.sendall(b"Level 8:\nDescription: Someone is watching the whole time. Do you like to check? If yes, go to hidden user; if no, exit the server.\n")
                    conn.sendall(b"Enter 'yes' to proceed or 'no' to exit: ")
                    response = conn.recv(1024).decode().strip().lower()

                    if response == 'yes':
                        # Give the first part of the flag
                        conn.sendall(b"Here is your first part of the flag: Scr3ws4ndB0lt5{Y0u'R3_uN8EaRA8ly\n")
                        conn.sendall(f"Now proceed to Watcher.\nLogin: Watcher\nPassword: ???\n".encode())

                        # Watcher level password handling
                        attempts = 0
                        while attempts < max_attempts:
                            conn.sendall(b"Enter password: ")
                            password = conn.recv(1024).decode().strip()

                            if password == levels[8]["password"]:
                                conn.sendall(f"Password correct! You've unlocked the Watcher's domain.\n".encode())
                                conn.sendall("Congratulations! You've completed Rise of Ultron.\nYour full flag is: Scr3ws4ndB0lt5{Y0u'R3_uN8EaRA8ly_n4ïv3}\n".encode())
                                break
                            else:
                                attempts += 1
                                conn.sendall(f"Incorrect password. You have {max_attempts - attempts} attempt(s) left.\n".encode())

                        if attempts == max_attempts:
                            conn.sendall(b"Too many incorrect attempts. Exiting the challenge.\n")
                    else:
                        conn.sendall(b"Exiting the challenge.\n")

# Run the server
if __name__ == "__main__":
    start_server()
