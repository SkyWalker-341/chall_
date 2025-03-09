# Bluetooth Keystroke Reconstruction CTF Challenge

## **Challenge Overview**
In this challenge, participants will analyze Bluetooth network traffic captured in a **Wireshark pcap file** to reconstruct keystrokes typed on an **AZERTY** keyboard. The reconstructed keystrokes contain a **Cooker’s Key**, which grants access to a website where the final flag can be retrieved.

---
## **Challenge Scenario**
An attacker used a Bluetooth keyboard to enter a secret **Cooker’s Key** while connected to a nearby system. The keystrokes were captured via Bluetooth sniffing, and the resulting traffic is provided as a **pcap file**.

Your task is to:
1. **Analyze the pcap file** to extract Bluetooth HID keystrokes.
2. **Reconstruct the typed text** while accounting for the **AZERTY layout**.
3. **Retrieve the Cooker’s Key** from the extracted keystrokes.
4. **Use the Cooker’s Key** on a website to obtain the flag.

---
## **Challenge Components**
- **pcap file**: Contains captured Bluetooth HID packets.
- **Scapy script**: Players may write or modify a script to extract and reconstruct keystrokes.
- **Website validation**: Entering the correct Cooker’s Key provides the CTF flag.

---
## **Technical Breakdown**
### **Step 1: Capturing Bluetooth Keystrokes**
- Use Wireshark with a Bluetooth-compatible adapter.
- Filter packets for **HID (Human Interface Device) Report Data**.
- Capture relevant keystroke data.

### **Step 2: Extracting Keystrokes with Scapy**
- Parse the **HID report descriptors** from the pcap file.
- Convert raw keycodes to corresponding **AZERTY** characters.
- Handle keypresses, releases, and modifier keys correctly.

### **Step 3: Reconstructing the Cooker’s Key**
- Arrange keystrokes in order to reveal the secret key.
- Ensure proper interpretation of **AZERTY keyboard layout**.

### **Step 4: Submitting the Cooker’s Key**
- Navigate to the provided **website URL**.
- Enter the correct key to unlock the **flag**.

---
## **Challenge Difficulty & Considerations**
### **Difficulty Level**: Hard
- Players must have **Wireshark**, **Scapy**, and **Bluetooth protocol** knowledge.
- The **AZERTY layout** adds complexity, requiring careful reconstruction.
- Players need to **script their own keystroke decoder** if no direct tool is available.

### **Hint for Players**
- Pay attention to **modifier keys (Shift, Ctrl, Alt)**.
- Understand how HID keycodes map to characters.
- AZERTY is different from QWERTY!

---

```
p3nt35t{Y0u_f1g0ut_k3y5tr0k3}
```



