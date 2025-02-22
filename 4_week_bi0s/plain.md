# Lab Summary

## Lab 1: Basic Linux & File Analysis
### Tasks:
1. Learn the OSI Model and their functionality:ipv4 and ipv6.  
2. **Installing a Virtual Machine** - Setting up a Linux VM and checking IP address.
3. **File Identification** - Extracting and analyzing file properties using `file`, `sha256sum`, `md5sum`, and `readelf`.
4. **Image Metadata Analysis** - Extracting geolocation data from an image using `exiftool`.
5. **Fixing Corrupt Files** - Using hex editors to repair file.
6. **Extracting Embedded Files** - Identifying hidden files inside images using `hexedit` and `binwalk`.
7. **File Encryption & Decryption** - Using GPG for symmetric encryption.
8. **SSH Configuration & Login** - Connecting to a guest VM via SSH and modifying port settings.
   
**Some challenge**

## Lab 2: Wireshark & Network Traffic Analysis
### Tasks:
1. **Wireshark Tutorial** - Capturing and analyzing TCP and HTTP traffic.
2. **TCP Chat Program** - Writing a chat server-client in C/Python and analyzing traffic using `tcpdump`.
3. **Netcat Chat Analysis** - Using `nc` for communication and filtering traffic with Wireshark.
4. **File Signature Analysis** - Using `nc` to transfer executables and recover them from PCAP using `tshark`.
5. **Python HTTP Server Traffic Capture** - Hosting a file server and extracting transferred files from traffic.
6. **ICMP Packet Capture** - Sending roll number via `ping` and analyzing traffic with `tshark`.
7. **FTP Setup with vsftpd** - Configuring an FTP server and capturing unencrypted/encrypted traffic.
**Some challenge**

## Lab 5: Advanced Linux & Encryption
### Tasks:
1. **Bandit Wargame (Level 15-31)** - Advanced Linux exercises.
2. **Linux Terminal Commands** - Process listing, socket analysis, filesystem queries.
3. **Disk Image Handling** - Mounting, modifying, and extracting data from disk images using a script.
4. **mem

**Some challenge** 

## Note on SSH and Netcat Communication
SSH provides secure encrypted communication between hosts, ensuring that all transmitted data remains confidential. When capturing SSH traffic in Wireshark, packets appear as encrypted blobs, making it impossible to directly view the data. 

Netcat (`nc`), on the other hand, transmits data in plaintext unless secured via SSH tunneling or an external encryption method. When analyzing Netcat traffic in Wireshark, unencrypted messages are visible, but encrypted transmissions appear as unreadable cipher text. Capturing and comparing both protocols in Wireshark helps demonstrate the importance of encryption in secure communications.

If Netcat is used for encryption, it is necessary to provide the corresponding decryption method. In SSH, the encryption is typically performed using algorithms like AES or ChaCha20, and decryption occurs automatically on the recipient's end using the negotiated session key. To analyze SSH traffic in Wireshark, one would need the private key to decrypt the captured packets. Without access to this key, decrypting SSH packets is practically infeasible due to strong encryption mechanisms in place. Therefore, when working with Netcat encryption, submitting the decryption method is essential to verify the integrity and security of the communication.



## Suggested Resources
- [Linux Command Handbook](https://www.digitalocean.com/community/tutorials/linux-commands) 
- [Wireshark User Guide](https://www.tpointtech.com/wireshark) 
- [Wireshark Cheat Sheet](https://www.stationx.net/wireshark-cheat-sheet/) 
- [tshark Manual](https://allabouttesting.org/tshark-basic-tutorial-with-practical-examples/) 
- [List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) 
- [ExifTool Documentation](https://wiki.bi0s.in/steganography/exiftool/) .
- [Binwalk for Firmware Analysis](https://wiki.bi0s.in/steganography/binwalk/) 
- [GPG Guide](https://www.devdungeon.com/content/gpg-tutorial) 
- [SSH Essentials](https://zah.uni-heidelberg.de/it-guide/ssh-tutorial-linux)
- [Netcat Tutorial](https://nooblinux.com/how-to-use-netcat/) 
   
