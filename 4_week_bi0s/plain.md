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
1. **Bandit Wargame (Level 15-31)** - Advanced Linux exercises.
2. **Linux Terminal Commands** - Process listing, socket analysis, filesystem queries.
3. **Disk Image Handling** - Mounting, modifying, and extracting data from disk images.
4. **GPG Encryption & Email Security** - Generating GPG keys and securing emails.
5. **Google Programmable Search Engine** - Automating searches using Python and Google API.
