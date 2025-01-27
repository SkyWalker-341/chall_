# Rise of Ultron

## Overview

This challenge consists of multiple levels, each utilizing a different networking protocol or concept. Participants will progress through the levels by analyzing network data and solving puzzles embedded in traffic captures or interactions.

## Challenge Theme

A hidden 8th level with the username **Watcher**.

The password for Watcher is a hash derived from the combination of two passwords from earlier levels (e.g., Level 2 and Level 6 passwords concatenated and hashed).

## Level Details

### Level 1 to Level 3

These levels provide foundational tasks to familiarize participants with basic network analysis and packet crafting.

### Level 4 (Hulk)

- **Protocol:** SMTP
- **Task:** Analyze email traffic to extract a clue or password embedded in the message body or headers.

### Level 5 (Thor)

- **Protocol:** DNS
- **Task:** Participants analyze DNS traffic to find a clue or password embedded in DNS query or response packets.

#### Implementation Idea for DNS

- Use a DNS query to `google.com` to simulate realistic traffic.
- Embed the password within a custom DNS response:
  - The DNS Name Header includes a hint or keyword, e.g., `exestr-clowns`.
  - The DNS Answer Section contains the password value (e.g., `Thor-password=ABC123!`).

Capture this interaction in a `.pcap` file for analysis in Wireshark.

#### Example of the DNS traffic:

- **Query:** `google.com` (simulated).
- **Response:** DNS Answer with `exestr-clowns.google.com` and `Thor-password=ABC123!` in the data.

### Level 6 (Iron Man)

- **Protocol:** TBD (can implement based on a unique mechanism, e.g., file transfer or HTTP interactions).
- **Task:** Requires analyzing or interacting with the network to uncover the password.

### Level 7 (Captain America)

- **Protocol:** Encrypted TCP (AES encryption)
- **Task:** Analyze encrypted TCP traffic to decrypt the content using a provided key or to uncover the encryption key within the traffic.

### Final Level (Watcher - Level 8)

- **Task:** Combine passwords from specific levels (e.g., Level 2 and Level 6).
- **Hashing:** Concatenate the passwords, hash them using a specific algorithm (e.g., SHA-256), and use the hash as the password for the Watcher account.

## Notes

- Ensure each `.pcap` file is realistic and matches the described protocol.
- Provide subtle hints for each level to guide participants while maintaining difficulty.
- Emphasize analysis skills using Wireshark, Scapy, and other networking tools.
