# Secure Instant P2P Messenger

This project implements the assigned CS5173 secure instant point-to-point messaging tool for Alice and Bob.

## Requirements Covered

- Alice and Bob can send instant messages over a direct TCP connection.
- Both peers enter the same shared passphrase before connecting.
- The passphrase is never used directly as an encryption key.
- Messages are encrypted with AES-256-CBC, which uses a 256-bit key.
- OpenSSL's CBC mode provides PKCS#7 block padding.
- Every message uses a fresh random 128-bit IV, so repeated plaintext such as `ok` produces different ciphertext.
- Each encrypted message has an HMAC-SHA-256 authentication tag to detect tampering before decryption.
- The GUI displays sent ciphertext, received ciphertext, and decrypted plaintext.
- Keys are periodically updated after every 10 locally sent messages, and can also be updated manually with the `Rekey Now` button.

## Files

- `secure_p2p_messenger.py`: GUI, socket protocol, encryption, authentication, and rekeying.
- `Project.pdf`: original project instructions.

## How To Run

### Recommended macOS Setup With Conda

Apple's system Python uses deprecated Tcl/Tk 8.5, which can make the GUI render incorrectly. A normal Python `venv` does not fix this because it still uses the same Python executable and the same linked Tk library.

Conda can fix it because it installs a separate Python and Tk inside the environment:

```bash
conda env create -f environment.yml
conda activate secure-p2p
python secure_p2p_messenger.py --tk-version
python secure_p2p_messenger.py
```

The version check should show Tk `8.6` or newer, not Apple Tk `8.5`.

Run the built-in cryptographic self-test:

```bash
python3 secure_p2p_messenger.py --self-test
```

Check which Tk your Python is using:

```bash
python3 secure_p2p_messenger.py --tk-version
```

On macOS, avoid Apple's deprecated system Tk. If your GUI renders incorrectly, install a newer Python that bundles a modern Tcl/Tk:

```bash
brew install python-tk@3.12
python3.12 secure_p2p_messenger.py --tk-version
python3.12 secure_p2p_messenger.py
```

Or install the current macOS Python installer from python.org and run the app with that Python. Python.org's macOS builds bundle Tcl/Tk 8.6 instead of relying on Apple's deprecated system copy.

Start Alice:

```bash
python3 secure_p2p_messenger.py
```

In Alice's window:

1. Set `Name` to `Alice`.
2. Enter a shared passphrase.
3. Set `Listen port` to `5000`.
4. Click `Start Listening`.

Start Bob in another terminal:

```bash
python3 secure_p2p_messenger.py
```

In Bob's window:

1. Set `Name` to `Bob`.
2. Enter the same shared passphrase.
3. Set `Peer host` to Alice's IP address, or `127.0.0.1` if both windows are on the same machine.
4. Set `Peer port` to `5000`.
5. Click `Connect`.

After the connection status says connected, either peer can type a message and click `Send`.

## Design Notes

### Cipher

The project uses AES-256-CBC through the system `openssl` command. AES-256 has a 256-bit key, which is much larger than the minimum 56-bit key length required by the assignment.

### Key Generation

Alice and Bob each generate a random handshake salt and exchange it in a `HELLO` frame. Both peers sort and hash the two salts to produce a common salt, then run:

```text
PBKDF2-HMAC-SHA-256(passphrase, combined_salt, 200000 iterations)
```

The PBKDF2 output becomes a shared chain secret. Per-epoch encryption and MAC keys are derived from that chain secret with HMAC-SHA-256.

### Padding

AES-CBC is a block cipher mode, so plaintext must be padded to a 16-byte boundary. OpenSSL's AES-CBC implementation applies standard PKCS#7 padding by default.

### Different Ciphertext For Repeated Messages

Each message uses a new random 16-byte IV. The IV is included with the ciphertext frame. Because CBC encryption depends on the IV, the same plaintext encrypted twice under the same key produces different ciphertext.

### Integrity

Encryption alone does not prove that a ciphertext was not modified. Each message includes:

```text
HMAC-SHA-256(mac_key, "DATA" || epoch || IV || ciphertext)
```

The receiver verifies this tag before decrypting.

### Connection Setup

One peer clicks `Start Listening`, which opens a TCP server socket. The other peer enters the listener's host and port and clicks `Connect`. After the socket connects, both peers exchange `HELLO` frames and derive the same session keys from the shared passphrase.

### Key Management

The session has an epoch number. A rekey operation sends an authenticated `REKEY` frame containing a fresh random nonce. Both peers update the chain secret with:

```text
HMAC-SHA-256(old_chain_secret, "secure-p2p-rekey-v1" || next_epoch || nonce)
```

Then they derive new AES and HMAC keys for the new epoch. This limits the amount of data protected by one key and reduces the impact if one epoch key is later exposed.
