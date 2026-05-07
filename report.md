# Secure Instant Point-to-Point Messaging Report

## 1. Project Overview

This project implements a secure instant messaging tool for Alice and Bob. The program provides a graphical user interface, a TCP socket connection, encrypted message transmission, ciphertext display, plaintext recovery, and periodic key updates.

Alice and Bob can run two copies of `secure_p2p_messenger.py`. One peer starts in **Listen** mode and the other peer starts in **Connect** mode. After a secure session is ready, either side can send messages.

## 2. Cipher Selection

The system uses **AES-256-GCM** from the Python `cryptography` package.

AES-256 uses a 256-bit key, which is greater than the required minimum of 56 bits. GCM mode provides both confidentiality and integrity. This means the message is encrypted, and the receiver can also detect whether the ciphertext, nonce, authentication tag, or associated metadata was modified.

## 3. Key Generation from Shared Password

The password is not used directly as the AES key. Instead, Alice and Bob type the same passphrase into their local GUI. After the TCP connection is established, the listener sends a fresh random 16-byte session salt to the connector. The program derives a 256-bit root secret using:

- PBKDF2-HMAC-SHA256
- 200,000 iterations
- A fresh session salt
- 32-byte output

Because Alice and Bob use the same passphrase, the same session salt, and the same PBKDF2 parameters, they derive the same root secret independently. An attacker who sees the network traffic may see the salt, but the salt is not secret and does not reveal the passphrase or the derived key. A fresh salt also prevents the same passphrase from producing the same root key in every chat session.

## 4. Padding Design

The project uses AES-GCM, which does not require padding. This is better than using a block mode that requires manual padding because incorrect padding handling can introduce security bugs. The plaintext can be any UTF-8 message length, including short messages such as `ok`.

## 5. Random Nonces and Different Ciphertexts

Every message uses a fresh random 96-bit nonce generated with `os.urandom(12)`. AES-GCM encryption uses the nonce, the epoch key, and the plaintext.

If Alice sends the same plaintext multiple times, the nonce changes each time. Therefore the resulting ciphertext changes each time. This prevents an observer from learning that two encrypted messages contain the same plaintext.

## 6. GUI Functions

The GUI is implemented with Python Tkinter. It supports:

- Choosing **Listen** or **Connect**
- Entering host and port
- Entering a shared passphrase
- Selecting password mode or X25519 handshake mode
- Sending plaintext messages
- Displaying sent ciphertext
- Displaying received ciphertext
- Displaying decrypted plaintext
- Showing session status and key fingerprint information

When Alice sends a message, her GUI shows the nonce, key epoch, and ciphertext plus authentication tag. When Bob receives it, Bob's GUI shows the received ciphertext and the decrypted plaintext.

## 7. Network Connection

The project uses TCP sockets.

One peer creates a server socket with `bind`, `listen`, and `accept`. The other peer uses `connect` to reach the listener. After the connection is established, messages are exchanged as length-prefixed JSON frames.

Each encrypted message frame contains:

- `type`: message
- `epoch`: key epoch number
- `nonce`: Base64-encoded AES-GCM nonce
- `ciphertext`: Base64-encoded ciphertext and GCM authentication tag

Length-prefixed frames are used so the receiver can identify exactly where each JSON message starts and ends.

## 8. Key Management and Periodic Updates

The program does not use one AES key forever. It derives a new AES-256 message key for each epoch using HKDF-SHA256:

`epoch_key = HKDF(root_secret, info = "CS5173 secure p2p messenger epoch N")`

The sender rotates to a new epoch after 5 sent messages or 120 seconds, whichever happens first. The epoch number is included in the encrypted message metadata, so the receiver can derive the same epoch key and decrypt the message.

This improves security because less data is protected by any single AES key. If an epoch key were somehow exposed, only messages in that epoch would be affected. HKDF also provides cryptographic separation between keys for different epochs.

## 9. Integrity and Authentication

AES-GCM produces an authentication tag. The receiver verifies this tag automatically during decryption. If an attacker modifies any bit of the ciphertext or uses the wrong key, decryption fails and the GUI displays an authentication error.

The epoch number is included as associated authenticated data. This prevents an attacker from moving ciphertext between key epochs without detection.

## 10. Extra Credit: No Pre-Shared Password Mode

The project includes an optional **X25519 handshake** mode. In this mode, Alice and Bob do not need a shared password.

The handshake works as follows:

1. Each peer generates a temporary X25519 private/public key pair.
2. The peers exchange public keys over the TCP connection.
3. Each peer computes the same Diffie-Hellman shared secret.
4. HKDF-SHA256 derives the AES root secret from the shared secret and handshake transcript.
5. The GUI displays a SHA-256 fingerprint of the handshake transcript.

Alice and Bob should compare the displayed fingerprint over a trusted side channel, such as a phone call or in-person comparison. If the fingerprints match, they know they derived the same key and no man-in-the-middle attacker changed the handshake keys.

This gives forward secrecy because the X25519 private keys are temporary and are not saved after the program exits.

## 11. Major Functions

`derive_password_root(passphrase)` derives the root secret from the shared passphrase using PBKDF2-HMAC-SHA256.

`derive_epoch_key(root_secret, epoch)` derives each AES-GCM epoch key using HKDF-SHA256.

`SecureSession.encrypt(plaintext)` generates a random nonce, encrypts the plaintext with AES-256-GCM, and returns a JSON-ready payload.

`SecureSession.decrypt(payload)` extracts the epoch, nonce, and ciphertext, derives the correct epoch key, verifies the AES-GCM tag, and returns the plaintext.

`PeerConnection.listen(...)` starts the server side of the TCP connection.

`PeerConnection.connect(...)` starts the client side of the TCP connection.

`MessengerGUI` builds the graphical interface, displays ciphertext and plaintext, and calls the networking and cryptographic functions.

## 12. Testing Plan and Screenshots

Suggested report screenshots:

1. Alice in Listen mode and Bob in Connect mode.
2. Both peers showing "Secure session ready".
3. Alice sending `ok` once and Bob receiving the ciphertext and plaintext.
4. Alice sending `ok` again, showing a different nonce and different ciphertext.
5. Several sent messages showing the epoch number increasing after key rotation.
6. Optional X25519 mode with matching fingerprints displayed on both peers.

## 13. Conclusion

The project satisfies the main requirements by using a modern cipher with a key length greater than 56 bits, deriving keys from a passphrase instead of using the password directly, avoiding padding mistakes with AES-GCM, using random nonces for different ciphertexts, providing a GUI, maintaining a TCP socket connection, and periodically rotating encryption keys.
