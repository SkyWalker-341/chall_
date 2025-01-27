# Rise of Ultron

## Overview

This challenge consists of multiple levels, each utilizing a different networking protocol or concept. Participants will progress through the levels by analyzing network data and solving puzzles embedded in traffic captures or interactions.

## Challenge Theme

A hidden 8th level with the username **Watcher**.

The password for Watcher is a hash derived from the combination of two passwords from earlier levels (e.g., Level 2 and Level 6 passwords concatenated and hashed).

## Level Details

### Level 1

- **Protocol:** ICMP
- **Task:** Sending an individual ICMP packet for each character

### Level 2

- **Protocol:** FTP
- **Task:** The file send througth FTP and flag is encrypted 

### Level 3 

- **Protocol:** HTTP 
- **Task:** The proper HTTP protocol format. In HTTP, a client sends a request to a server, and the server responds with a response

  
### Level 4 (Hulk)

- **Protocol:** SMTP
- **Task:** This challenge involves creating and manipulating SMTP packets within a `.pcap` file, where packets can be "hidden" by altering their timestamps. Participants must reverse the timestamp modifications to uncover hidden messages.


### Level 5 (Thor)

- **Protocol:** DNS
- **Task:** Participants analyze DNS traffic to find a clue or password embedded in DNS query or response packets.

### Level 6 (Iron Man)

- **Protocol:** SMB
- **Task:** The SMB package are encrypted to decrypted the packages you need session ID and Session key but there are multip Session ID was there and SMB contains a pasword and a encrypted key-log file 

### Level 7 (Captain America)

- **Protocol:** Encrypted TCP (AES encryption)
- **Task:** Analyze encrypted TCP traffic to decrypt the content using a key-log file which you uncover in SMB. the encryption tcp contains a encrypted password and a binary file. To get the original password reverse the binary file and get the password 

### Final Level (Watcher - Level 8)

- **Task:** Combine passwords from specific levels (e.g., Level 2 and Level 6).
- **Hashing:** Concatenate the passwords, hash them using a specific algorithm (e.g., SHA-256), and use the hash as the password for the Watcher account (hashing format is iron-password_thor-password)only the password need to be hashing.

