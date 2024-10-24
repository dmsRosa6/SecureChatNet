# A Secure Multicast Protocol for a Peer-Group Messaging System

## Project Overview

The Secure Multicast Protocol for a Peer-Group Messaging System is designed to facilitate secure communication within a peer-to-peer messaging system using UDP and IP Multicasting. The protocol addresses essential security concerns such as confidentiality, integrity, authentication, and protection against replay attacks, making it suitable for secure group communication.

## Objectives

- **Confidentiality**: Ensure that messages are only accessible to valid users, preventing unauthorized access.
- **Integrity**: Protect messages from alteration during transmission, enabling detection of tampered messages.
- **Replay Attack Prevention**: Implement mechanisms to detect and discard replayed messages from unauthorized users.
- **Peer Authentication**: Use digital signatures to verify the identity of message senders, ensuring all messages originate from legitimate users.

## Packet Structure

The message packets in the SMP4PGMS protocol are structured as follows:

**MESSAGE** = Control-Header || ChatMessagePayload || SIGNATURE || MacProof

### Components:

1. **Control-Header**
   - **VERSION**: A short integer indicating the protocol version.
   - **MAGIC_NUMBER**: A long integer that serves as a unique identifier for the chat session.
   - **HASH_USERNAME**: A SHA256 hash of the user's nickname, ensuring anonymity and integrity.

2. **ChatMessagePayload**
   - **NONCE**: A 128-bit random number generated by the sender to prevent replay attacks.
   - **MSG_TYPE**: Indicates the type of message (e.g., text, file).
   - **USERNAME**: The sender's username.
   - **MESSAGE**: The actual content being sent, which is encrypted to ensure confidentiality.

3. **SIGNATURE**
   - A digital signature generated using the sender's private key, providing authenticity and integrity to the message.

4. **MAC-PROOF**
   - A message authentication code (HMAC) that ensures message integrity and prevents tampering.

### Dependencies

This project relies on the **Bouncy Castle** library for cryptographic operations, including hashing, encryption, and digital signatures. Make sure to include the Bouncy Castle library in your project to handle the cryptographic functionalities.

## How to Use

To run the chat client, use the following command:

```bash
java -Djava.net.preferIPv4Stack=true MChatCliente nickname mcast-addr port
```
### Parameters:

- **nickname**: The user's nickname (e.g., hj).
- **mcast-addr**: A multicast IP address (e.g., 224.10.10.10) within the range of 224.0.0.1 to 239.255.255.255.
- **port**: A UDP port number (e.g., 9000). Any available UDP port can be used.

### Important Notes:

- **IPv4 Requirement**: Due to compatibility issues with dual-stack operating systems (supporting both IPv4 and IPv6), it is essential to specify the use of the IPv4 stack with the `-Djava.net.preferIPv4Stack=true` flag.
- **Avoid Special Loopback Address**: Do not use the address 224.0.0.1, as it is reserved for loopback purposes.

### Example Commands

To run the chat client, you can use commands such as:

```bash
java -Djava.net.preferIPv4Stack=true MChatCliente bob 224.4.4.4 9000
```

## Testing

For testing the implementation, **Wireshark** was used to capture and analyze the packets transmitted over the network. This tool allows you to monitor the data flow, verify the structure of the packets, and ensure that the encryption and authentication mechanisms are functioning correctly. By inspecting the packets in Wireshark, you can confirm that messages are being sent securely and that the proper headers, payloads, signatures, and MAC proofs are included in each packet.

## Future Work

Future enhancements may focus on improving peer authentication mechanisms and adding more dynamic configurations to the messaging protocol.

## Dependencies

- **Bouncy Castle**: The implementation relies on the Bouncy Castle library for cryptographic operations. Ensure you have the library included in your project to handle encryption, decryption, and digital signatures.

# Disclaimer
This document serves solely as a personal reference for educational purposes :)
