# Lab Summary

## Lab 1: Basic Linux & File Analysis
### Tasks:
1. **Installing a Virtual Machine** - Setting up a Linux VM and checking IP address.
2. **File Identification** - Extracting and analyzing file properties using `file`, `sha256sum`, `md5sum`, and `readelf`.
3. **Image Metadata Analysis** - Extracting geolocation data from an image using `exiftool`.
4. **Fixing Corrupt PNG Files** - Using hex editors to repair PNG file signatures.
5. **Extracting Embedded Files** - Identifying hidden ZIP files inside images using `hexedit` and `binwalk`.
6. **File Encryption & Decryption** - Using GPG for symmetric encryption.
7. **SSH Configuration & Login** - Connecting to a guest VM via SSH and modifying port settings.

## Lab 2: Wireshark & Network Traffic Analysis
### Tasks:
1. **Wireshark Tutorial** - Capturing and analyzing TCP and HTTP traffic.
2. **TCP Chat Program** - Writing a chat server-client in C/Python and analyzing traffic using `tcpdump`.
3. **Netcat Chat Analysis** - Using `nc` for communication and filtering traffic with Wireshark.

## Lab 3: Network Traffic Analysis with tshark
### Tasks:
1. **File Signature Analysis** - Using `nc` to transfer executables and recover them from PCAP using `tshark`.
2. **Python HTTP Server Traffic Capture** - Hosting a file server and extracting transferred files from traffic.
3. **ICMP Packet Capture** - Sending roll number via `ping` and analyzing traffic with `tshark`.

## Lab 4: SSH Tunneling & FTP Setup
### Tasks:
1. **Host-Only Adapter in VirtualBox** - Setting up networking between host and guest VM.
2. **File Transfer via SCP** - Observing differences between `scp` and `nc`.
3. **SSH Port Forwarding** - Encrypting HTTP traffic using SSH tunnels.
4. **FTP Setup with vsftpd** - Configuring an FTP server and capturing unencrypted/encrypted traffic.

## Lab 5: Advanced Linux & Encryption
### Tasks:
1. **Linux Terminal Commands** - Process listing, socket analysis, filesystem queries.
2. **Disk Image Handling** - Mounting, modifying, and extracting data from disk images.
3. **GPG Encryption & Email Security** - Generating GPG keys and securing emails.


## Note on SSH and Netcat Communication
SSH provides secure encrypted communication between hosts, ensuring that all transmitted data remains confidential. When capturing SSH traffic in Wireshark, packets appear as encrypted blobs, making it impossible to directly view the data. 

Netcat (`nc`), on the other hand, transmits data in plaintext unless secured via SSH tunneling or an external encryption method. When analyzing Netcat traffic in Wireshark, unencrypted messages are visible, but encrypted transmissions appear as unreadable cipher text. Capturing and comparing both protocols in Wireshark helps demonstrate the importance of encryption in secure communications.

If Netcat is used for encryption, it is necessary to provide the corresponding decryption method. In SSH, the encryption is typically performed using algorithms like AES or ChaCha20, and decryption occurs automatically on the recipient's end using the negotiated session key. To analyze SSH traffic in Wireshark, one would need the private key to decrypt the captured packets. Without access to this key, decrypting SSH packets is practically infeasible due to strong encryption mechanisms in place. Therefore, when working with Netcat encryption, submitting the decryption method is essential to verify the integrity and security of the communication.
