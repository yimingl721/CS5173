# Secure Instant Point-to-Point Messaging Report

## 1. Project Overview

This project implements a secure instant messaging tool for Alice and Bob. The program provides a graphical user interface, a TCP socket connection, encrypted message transmission, ciphertext display, plaintext recovery, message authentication, and periodic key updates.

Alice and Bob run two copies of `secure_p2p_messenger.py`. One peer clicks **Start Listening** to open a server socket. The other peer enters the listener's host and port and clicks **Connect**. After the secure session is ready, either side can send messages.

## 2. Cipher Selection

The system uses **AES-256-CBC** through the system `openssl` command.

AES-256 uses a 256-bit encryption key, which is greater than the assignment requirement of at least 56 bits. CBC mode provides confidentiality. Because CBC mode does not provide integrity by itself, the project also computes a separate **HMAC-SHA-256** authentication tag for each encrypted message.

The effective message protection is:

```text
AES-256-CBC encryption + HMAC-SHA-256 authentication
```

This encrypt-then-MAC design lets the receiver detect tampering before attempting decryption.

## 3. Key Generation from Shared Password

The password is never used directly as the AES key. Alice and Bob type the same shared passphrase into their local GUI. During connection setup, both peers generate a fresh random 16-byte salt and exchange it in a `HELLO` frame.

Both peers sort the two salts, hash them together, and then derive a shared 32-byte chain secret using:

```text
PBKDF2-HMAC-SHA-256(passphrase, combined_salt, 200000 iterations)
```

Because both sides use the same passphrase, the same two salts, and the same PBKDF2 parameters, they independently derive the same chain secret. The salts are not secret, but they ensure that the same passphrase does not produce the same session keys every time.

For each key epoch, the program derives 64 bytes of key material from the chain secret using an HMAC-SHA-256 based derivation function:

- first 32 bytes: AES-256 encryption key
- last 32 bytes: HMAC-SHA-256 MAC key

## 4. Padding Design

AES-CBC is a block cipher mode, so plaintext must be padded to a 16-byte block boundary. The project uses OpenSSL's AES-CBC implementation, which applies standard **PKCS#7 padding** by default.

This means messages of any length can be encrypted, including short messages such as `ok`.

## 5. Random IVs and Different Ciphertexts

Every message uses a fresh random 16-byte IV generated with:

```python
os.urandom(16)
```

The IV is sent with the encrypted frame. Because CBC encryption depends on the IV, sending the same plaintext multiple times produces different ciphertext each time. For example, if Alice sends `ok` twice, the IV changes, so the ciphertext also changes.

## 6. Message Integrity and Authentication

After encryption, the sender computes:

```text
HMAC-SHA-256(mac_key, "DATA" || epoch || IV || ciphertext)
```

The HMAC tag is sent with the message. The receiver recomputes the expected tag and compares it using `hmac.compare_digest`, which is designed for constant-time comparison.

If the ciphertext, IV, epoch, or tag is modified, verification fails and the message is rejected before decryption. This prevents unauthenticated ciphertext from being decrypted.

## 7. GUI Functions

The GUI is implemented with Python Tkinter. The project uses a conda environment with Tcl/Tk 8.6 or newer because Apple's system Tk 8.5 is deprecated and rendered the GUI incorrectly on macOS.

The GUI supports:

- entering a local display name
- entering a shared passphrase
- entering listen port
- entering peer host and peer port
- starting a listener
- connecting to a listener
- sending plaintext messages
- displaying sent ciphertext
- displaying received ciphertext
- displaying decrypted plaintext
- manually rotating keys with **Rekey Now**
- closing the session

When Alice sends a message, her GUI displays the sent ciphertext. When Bob receives it, Bob's GUI displays the received ciphertext and decrypted plaintext.

## 8. Network Connection

The project uses TCP sockets.

The listener calls:

```text
socket()
bind()
listen()
accept()
```

The connector calls:

```text
socket.create_connection()
```

After the socket connects, both peers exchange `HELLO` frames containing:

- protocol version
- display name
- random salt
- cipher description
- KDF description

Application messages are sent as length-prefixed JSON frames. A 4-byte big-endian length field is sent first, followed by the UTF-8 JSON payload. This lets the receiver identify exactly where each message starts and ends on the TCP stream.

Encrypted data frames contain:

- `type`: `DATA`
- `sender`: sender display name
- `epoch`: current key epoch
- `iv`: Base64-encoded AES-CBC IV
- `ciphertext`: Base64-encoded ciphertext
- `tag`: Base64-encoded HMAC tag

## 9. Key Management and Periodic Updates

The program does not use one encryption key forever. It maintains an epoch number. Each epoch has a separate AES key and HMAC key derived from the current chain secret.

The program automatically rekeys after every 10 locally sent messages. The user can also click **Rekey Now**.

A rekey operation sends an authenticated `REKEY` frame containing:

- next epoch number
- fresh random 32-byte nonce
- HMAC tag over the rekey data

Both peers update the chain secret with:

```text
HMAC-SHA-256(old_chain_secret, "secure-p2p-rekey-v1" || next_epoch || nonce)
```

Then both sides derive new AES and HMAC keys for the new epoch.

This improves security because less traffic is protected by any single key. If one epoch key were later exposed, future epochs would still be protected by newly derived key material.

## 10. Major Functions

`CryptoContext.__init__` derives the shared chain secret from the passphrase and exchanged salts using PBKDF2-HMAC-SHA-256.

`CryptoContext._derive_epoch_keys` derives the AES encryption key and HMAC key for the current epoch.

`CryptoContext.encrypt` generates a random IV, encrypts the plaintext with AES-256-CBC, and computes the HMAC tag.

`CryptoContext.decrypt` verifies the HMAC tag and decrypts the ciphertext only if authentication succeeds.

`CryptoContext.make_rekey_frame` creates an authenticated key update frame and advances the local epoch.

`CryptoContext.accept_rekey_frame` verifies a received rekey frame and advances the receiver to the new epoch.

`PeerSession.start` exchanges `HELLO` frames and initializes the secure session.

`send_frame` and `recv_frame` implement length-prefixed JSON framing over TCP.

`SecureMessengerApp` builds the GUI and connects user actions to the secure networking layer.

## 11. Testing Plan and Screenshots

Suggested report screenshots:

1. Alice's GUI with name, passphrase, listen port, and **Start Listening**.
2. Bob's GUI with name, passphrase, peer host, peer port, and **Connect**.
3. Both peers showing a connected status.
4. Alice sending `ok` once and Bob displaying the received ciphertext and plaintext.
5. Alice sending `ok` again, showing a different ciphertext.
6. Manual key update using **Rekey Now**.
7. Automatic key update after 10 sent messages.

The built-in self-test can be run with:

```bash
python secure_p2p_messenger.py --self-test
```

The test verifies:

- repeated plaintext produces different ciphertext
- Alice and Bob derive compatible keys from the same passphrase
- rekeying synchronizes both peers to the same epoch
- tampered ciphertext fails HMAC verification

## 12. Environment Setup

The repository includes `environment.yml` for conda:

```bash
conda env create -f environment.yml
conda activate secure-p2p
python secure_p2p_messenger.py --tk-version
python secure_p2p_messenger.py
```

The `--tk-version` option confirms that the program is using Tcl/Tk 8.6 or newer instead of Apple's deprecated system Tk 8.5.

## 13. Conclusion

The project satisfies the main requirements by using a cipher with a key length greater than 56 bits, deriving encryption keys from a shared passphrase instead of using the password directly, applying PKCS#7 padding through OpenSSL, using random IVs so repeated messages encrypt differently, authenticating messages with HMAC-SHA-256, providing a GUI, maintaining a TCP socket connection, and periodically rotating keys.
