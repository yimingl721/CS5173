#!/usr/bin/env python3
"""Secure instant point-to-point messenger for the CS5173 final project.

The GUI uses Tkinter and the network path uses a direct TCP socket between two
peers. Message encryption is performed with the system OpenSSL command so the
project works without installing third-party Python packages.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import threading

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, simpledialog, scrolledtext, ttk
from typing import Callable, Optional


GUI_VERSION = "conda-tk-full-ui-v5"
PBKDF2_ITERATIONS = 200_000
REKEY_AFTER_SENT_MESSAGES = 10
FRAME_LIMIT = 1024 * 1024


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def hkdf_like(key: bytes, label: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(key, block + label + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


def openssl_aes_256_cbc(data: bytes, key: bytes, iv: bytes, decrypt: bool = False) -> bytes:
    action = "-d" if decrypt else "-e"
    command = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        action,
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
    ]
    result = subprocess.run(
        command,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"OpenSSL AES operation failed: {stderr}")
    return result.stdout


@dataclass
class EncryptedMessage:
    epoch: int
    iv: bytes
    ciphertext: bytes
    tag: bytes

    def to_frame(self, sender: str) -> dict:
        return {
            "type": "DATA",
            "sender": sender,
            "epoch": self.epoch,
            "iv": b64e(self.iv),
            "ciphertext": b64e(self.ciphertext),
            "tag": b64e(self.tag),
        }


class CryptoContext:
    def __init__(self, passphrase: str, local_salt: bytes, peer_salt: bytes):
        if not passphrase:
            raise ValueError("A shared passphrase is required.")
        ordered_salts = sorted([local_salt, peer_salt])
        salt = hashlib.sha256(b"secure-p2p-salt-v1" + ordered_salts[0] + ordered_salts[1]).digest()
        self.chain_secret = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
            dklen=32,
        )
        self.epoch = 0
        self._derive_epoch_keys()

    def _derive_epoch_keys(self) -> None:
        key_material = hkdf_like(
            self.chain_secret,
            b"secure-p2p-message-keys-v1:" + str(self.epoch).encode("ascii"),
            64,
        )
        self.enc_key = key_material[:32]
        self.mac_key = key_material[32:]

    def encrypt(self, plaintext: str) -> EncryptedMessage:
        iv = os.urandom(16)
        ciphertext = openssl_aes_256_cbc(plaintext.encode("utf-8"), self.enc_key, iv)
        tag = self._message_tag(self.epoch, iv, ciphertext)
        return EncryptedMessage(self.epoch, iv, ciphertext, tag)

    def decrypt(self, message: EncryptedMessage) -> str:
        if message.epoch != self.epoch:
            raise ValueError(f"Received epoch {message.epoch}, but local epoch is {self.epoch}.")
        expected_tag = self._message_tag(message.epoch, message.iv, message.ciphertext)
        if not constant_time_equal(expected_tag, message.tag):
            raise ValueError("Message authentication failed. The ciphertext may be corrupted.")
        plaintext = openssl_aes_256_cbc(message.ciphertext, self.enc_key, message.iv, decrypt=True)
        return plaintext.decode("utf-8")

    def make_rekey_frame(self, sender: str) -> dict:
        nonce = os.urandom(32)
        next_epoch = self.epoch + 1
        tag = self._rekey_tag(next_epoch, nonce)
        self._apply_rekey(next_epoch, nonce)
        return {
            "type": "REKEY",
            "sender": sender,
            "epoch": next_epoch,
            "nonce": b64e(nonce),
            "tag": b64e(tag),
        }

    def accept_rekey_frame(self, frame: dict) -> int:
        next_epoch = int(frame["epoch"])
        nonce = b64d(frame["nonce"])
        tag = b64d(frame["tag"])
        if next_epoch != self.epoch + 1:
            raise ValueError(f"Unexpected rekey epoch {next_epoch}; expected {self.epoch + 1}.")
        expected_tag = self._rekey_tag(next_epoch, nonce)
        if not constant_time_equal(expected_tag, tag):
            raise ValueError("Rekey authentication failed.")
        self._apply_rekey(next_epoch, nonce)
        return self.epoch

    def _message_tag(self, epoch: int, iv: bytes, ciphertext: bytes) -> bytes:
        data = b"DATA" + struct.pack("!Q", epoch) + iv + ciphertext
        return hmac.new(self.mac_key, data, hashlib.sha256).digest()

    def _rekey_tag(self, next_epoch: int, nonce: bytes) -> bytes:
        data = b"REKEY" + struct.pack("!Q", next_epoch) + nonce
        return hmac.new(self.mac_key, data, hashlib.sha256).digest()

    def _apply_rekey(self, next_epoch: int, nonce: bytes) -> None:
        data = b"secure-p2p-rekey-v1" + struct.pack("!Q", next_epoch) + nonce
        self.chain_secret = hmac.new(self.chain_secret, data, hashlib.sha256).digest()
        self.epoch = next_epoch
        self._derive_epoch_keys()


def send_frame(sock: socket.socket, frame: dict, send_lock: threading.Lock) -> None:
    payload = json.dumps(frame, separators=(",", ":")).encode("utf-8")
    if len(payload) > FRAME_LIMIT:
        raise ValueError("Frame is too large.")
    with send_lock:
        sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Peer closed the connection.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> dict:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > FRAME_LIMIT:
        raise ValueError(f"Invalid frame length: {length}")
    payload = recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))


class PeerSession:
    def __init__(
        self,
        sock: socket.socket,
        passphrase: str,
        local_name: str,
        on_status: Callable[[str], None],
        on_sent: Callable[[str, str], None],
        on_received: Callable[[str, str, str], None],
        on_close: Callable[[str], None],
    ):
        self.sock = sock
        self.passphrase = passphrase
        self.local_name = local_name or "Me"
        self.on_status = on_status
        self.on_sent = on_sent
        self.on_received = on_received
        self.on_close = on_close
        self.crypto: Optional[CryptoContext] = None
        self.peer_name = "Peer"
        self.send_lock = threading.Lock()
        self.closed = threading.Event()
        self.sent_since_rekey = 0

    def start(self) -> None:
        local_salt = os.urandom(16)
        hello = {
            "type": "HELLO",
            "version": 1,
            "name": self.local_name,
            "salt": b64e(local_salt),
            "cipher": "AES-256-CBC+HMAC-SHA256",
            "kdf": f"PBKDF2-HMAC-SHA256/{PBKDF2_ITERATIONS}",
        }
        send_frame(self.sock, hello, self.send_lock)
        peer_hello = recv_frame(self.sock)
        if peer_hello.get("type") != "HELLO":
            raise ValueError("Peer did not send a HELLO frame.")
        self.peer_name = str(peer_hello.get("name") or "Peer")
        self.crypto = CryptoContext(self.passphrase, local_salt, b64d(peer_hello["salt"]))
        self.on_status(
            f"Connected to {self.peer_name}. Cipher AES-256-CBC, epoch {self.crypto.epoch}."
        )
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def send_message(self, plaintext: str) -> None:
        if not self.crypto:
            raise RuntimeError("Session is not ready.")
        message = self.crypto.encrypt(plaintext)
        frame = message.to_frame(self.local_name)
        send_frame(self.sock, frame, self.send_lock)
        self.sent_since_rekey += 1
        self.on_sent(plaintext, b64e(message.ciphertext))
        if self.sent_since_rekey >= REKEY_AFTER_SENT_MESSAGES:
            self.rekey(reason="automatic")

    def rekey(self, reason: str = "manual") -> None:
        if not self.crypto:
            raise RuntimeError("Session is not ready.")
        frame = self.crypto.make_rekey_frame(self.local_name)
        send_frame(self.sock, frame, self.send_lock)
        self.sent_since_rekey = 0
        self.on_status(f"Sent {reason} rekey. New epoch {self.crypto.epoch}.")

    def close(self) -> None:
        self.closed.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _receive_loop(self) -> None:
        try:
            while not self.closed.is_set():
                frame = recv_frame(self.sock)
                frame_type = frame.get("type")
                if frame_type == "DATA":
                    self._handle_data(frame)
                elif frame_type == "REKEY":
                    self._handle_rekey(frame)
                else:
                    raise ValueError(f"Unknown frame type: {frame_type}")
        except Exception as exc:
            if not self.closed.is_set():
                self.closed.set()
                self.on_close(str(exc))

    def _handle_data(self, frame: dict) -> None:
        if not self.crypto:
            raise RuntimeError("Session is not ready.")
        message = EncryptedMessage(
            epoch=int(frame["epoch"]),
            iv=b64d(frame["iv"]),
            ciphertext=b64d(frame["ciphertext"]),
            tag=b64d(frame["tag"]),
        )
        plaintext = self.crypto.decrypt(message)
        sender = str(frame.get("sender") or self.peer_name)
        self.on_received(sender, b64e(message.ciphertext), plaintext)

    def _handle_rekey(self, frame: dict) -> None:
        if not self.crypto:
            raise RuntimeError("Session is not ready.")
        epoch = self.crypto.accept_rekey_frame(frame)
        sender = str(frame.get("sender") or self.peer_name)
        self.sent_since_rekey = 0
        self.on_status(f"Accepted rekey from {sender}. New epoch {epoch}.")


class SecureMessengerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure P2P Messenger")
        self.root.geometry("1060x760")
        self.root.minsize(900, 620)
        self.listener_socket: Optional[socket.socket] = None
        self.session: Optional[PeerSession] = None
        self.local_name = "Alice"
        self._configure_theme()
        self._build_ui()

    def _configure_theme(self) -> None:
        self.colors = {
            "window": "#20282b",
            "panel": "#20282b",
            "text": "#f8fafc",
            "muted": "#cbd5e1",
            "accent": "#60a5fa",
            "button": "#334155",
            "button_active": "#475569",
            "border": "#60a5fa",
            "field": "#111827",
            "field_text": "#ffffff",
        }
        self.root.configure(bg=self.colors["window"])
        self.root.option_add("*Font", "Helvetica 13")

    def _build_ui(self) -> None:
        main = tk.Frame(self.root, bg=self.colors["window"], padx=14, pady=14)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(1, weight=1)

        setup = tk.LabelFrame(
            main,
            text="Connection",
            bg=self.colors["panel"],
            fg=self.colors["text"],
            font=("Helvetica", 14, "bold"),
            padx=12,
            pady=12,
            bd=1,
            relief="solid",
            highlightbackground=self.colors["border"],
        )
        setup.grid(row=0, column=0, rowspan=3, sticky="nsw", padx=(0, 12))
        setup.columnconfigure(1, weight=1)

        self.name_var = tk.StringVar(value="Alice")
        self.pass_var = tk.StringVar()
        self.listen_port_var = tk.StringVar(value="5000")
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.peer_port_var = tk.StringVar(value="5000")
        self.status_var = tk.StringVar(value="Idle")
        self.message_var = tk.StringVar()

        fields = [
            ("Name", self.name_var, False),
            ("Shared passphrase", self.pass_var, True),
            ("Listen port", self.listen_port_var, False),
            ("Peer host", self.host_var, False),
            ("Peer port", self.peer_port_var, False),
        ]
        for row, (label, variable, secret) in enumerate(fields):
            self._make_label(setup, label).grid(row=row, column=0, sticky="w", pady=5, padx=(0, 8))
            entry = self._make_entry(setup, variable, width=28, secret=secret)
            entry.grid(row=row, column=1, sticky="ew", pady=4)

        self._make_button(setup, text="Start Listening", command=self.start_listening).grid(
            row=5, column=0, columnspan=2, sticky="ew", pady=(12, 4)
        )
        self._make_button(setup, text="Connect", command=self.connect_to_peer).grid(
            row=6, column=0, columnspan=2, sticky="ew", pady=4
        )
        self._make_button(setup, text="Rekey Now", command=self.rekey_now).grid(
            row=7, column=0, columnspan=2, sticky="ew", pady=4
        )
        self._make_button(setup, text="Close Session", command=self.close_session).grid(
            row=8, column=0, columnspan=2, sticky="ew", pady=4
        )
        status_label = self._make_label(setup, "")
        status_label.configure(textvariable=self.status_var, wraplength=260, justify="left", fg=self.colors["muted"])
        status_label.grid(row=9, column=0, columnspan=2, sticky="ew", pady=(14, 0))

        conversation_box = tk.LabelFrame(
            main,
            text="Conversation",
            bg=self.colors["panel"],
            fg=self.colors["text"],
            font=("Helvetica", 14, "bold"),
            padx=10,
            pady=10,
            bd=1,
            relief="solid",
            highlightbackground=self.colors["border"],
        )
        conversation_box.grid(row=0, column=1, sticky="nsew")
        conversation_box.columnconfigure(0, weight=1)
        conversation_box.rowconfigure(0, weight=1)
        self.conversation = self._make_text(conversation_box, height=18, state="disabled")
        self.conversation.grid(row=0, column=0, sticky="nsew")

        cipher_box = tk.Frame(main, bg=self.colors["window"])
        cipher_box.grid(row=1, column=1, sticky="nsew", pady=10)
        cipher_box.columnconfigure(0, weight=1)
        cipher_box.columnconfigure(1, weight=1)
        cipher_box.rowconfigure(1, weight=1)

        self._make_label(cipher_box, "Last sent ciphertext", panel=False, bold=True).grid(
            row=0, column=0, sticky="w"
        )
        self._make_label(cipher_box, "Last received ciphertext / plaintext", panel=False, bold=True).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        self.sent_ciphertext = self._make_text(cipher_box, height=10)
        self.sent_ciphertext.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        self.received_details = self._make_text(cipher_box, height=10)
        self.received_details.grid(row=1, column=1, sticky="nsew", padx=(8, 0))

        send_box = tk.Frame(main, bg=self.colors["window"])
        send_box.grid(row=2, column=1, sticky="ew")
        send_box.columnconfigure(0, weight=1)
        self.message_entry = self._make_entry(send_box, self.message_var)
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.message_entry.bind("<Return>", lambda _event: self.send_message())
        self._make_button(send_box, text="Send", command=self.send_message).grid(row=0, column=1)

    def _make_label(self, parent: tk.Widget, text: str, panel: bool = True, bold: bool = False) -> tk.Label:
        return tk.Label(
            parent,
            text=text,
            bg=self.colors["panel"] if panel else self.colors["window"],
            fg=self.colors["text"],
            anchor="w",
            font=("Helvetica", 13, "bold") if bold else ("Helvetica", 13),
        )

    def _make_entry(
        self, parent: tk.Widget, variable: tk.StringVar, width: int = 32, secret: bool = False
    ) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=variable,
            width=width,
            show="*" if secret else "",
            bg=self.colors["field"],
            fg=self.colors["field_text"],
            insertbackground=self.colors["field_text"],
            relief="solid",
            bd=2,
            highlightthickness=2,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
        )

    def _make_button(
        self,
        parent: tk.Widget,
        text: str = "",
        command: Optional[Callable[[], None]] = None,
        textvariable: Optional[tk.StringVar] = None,
    ) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            textvariable=textvariable,
            command=command,
            bg=self.colors["button"],
            fg=self.colors["text"],
            activebackground=self.colors["button_active"],
            activeforeground=self.colors["text"],
            relief="raised",
            bd=1,
            padx=10,
            pady=6,
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            width=34,
        )

    def _make_text(self, parent: tk.Widget, height: int, state: str = "normal") -> scrolledtext.ScrolledText:
        widget = scrolledtext.ScrolledText(
            parent,
            height=height,
            state=state,
            bg=self.colors["field"],
            fg=self.colors["field_text"],
            insertbackground=self.colors["field_text"],
            selectbackground="#2563eb",
            selectforeground="#ffffff",
            relief="solid",
            borderwidth=2,
            highlightthickness=2,
            highlightbackground=self.colors["border"],
            font=("Menlo", 12),
            wrap="word",
        )
        return widget

    def start_listening(self) -> None:
        try:
            port = int(self.listen_port_var.get())
            passphrase = self._require_passphrase()
            local_name = self.name_var.get().strip() or "Me"
        except ValueError as exc:
            messagebox.showerror("Invalid setup", str(exc))
            return
        threading.Thread(target=self._listen_worker, args=(port, passphrase, local_name), daemon=True).start()

    def connect_to_peer(self) -> None:
        try:
            host = self.host_var.get().strip()
            port = int(self.peer_port_var.get())
            passphrase = self._require_passphrase()
            local_name = self.name_var.get().strip() or "Me"
            if not host:
                raise ValueError("Peer host is required.")
        except ValueError as exc:
            messagebox.showerror("Invalid setup", str(exc))
            return
        threading.Thread(target=self._connect_worker, args=(host, port, passphrase, local_name), daemon=True).start()

    def send_message(self) -> None:
        text = self.message_var.get()
        if not text:
            return
        if not self.session:
            messagebox.showerror("Not connected", "Start or connect to a peer first.")
            return
        try:
            self.session.send_message(text)
            self.message_var.set("")
        except Exception as exc:
            messagebox.showerror("Send failed", str(exc))

    def rekey_now(self) -> None:
        if not self.session:
            messagebox.showerror("Not connected", "Start or connect to a peer first.")
            return
        try:
            self.session.rekey()
        except Exception as exc:
            messagebox.showerror("Rekey failed", str(exc))

    def close_session(self) -> None:
        if self.session:
            self.session.close()
            self.session = None
        if self.listener_socket:
            try:
                self.listener_socket.close()
            except OSError:
                pass
            self.listener_socket = None
        self._set_status("Closed.")

    def _listen_worker(self, port: int, passphrase: str, local_name: str) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("", port))
            server.listen(1)
            self.listener_socket = server
            self._set_status(f"Listening on port {port}.")
            sock, address = server.accept()
            self._set_status(f"Accepted connection from {address[0]}:{address[1]}.")
            self._install_session(sock, passphrase, local_name)
        except Exception as exc:
            self._set_status(f"Listener error: {exc}")

    def _connect_worker(self, host: str, port: int, passphrase: str, local_name: str) -> None:
        try:
            self._set_status(f"Connecting to {host}:{port}...")
            sock = socket.create_connection((host, port), timeout=10)
            self._install_session(sock, passphrase, local_name)
        except Exception as exc:
            self._set_status(f"Connection error: {exc}")

    def _install_session(self, sock: socket.socket, passphrase: str, local_name: str) -> None:
        if self.session:
            self.session.close()
        self.local_name = local_name
        session = PeerSession(
            sock=sock,
            passphrase=passphrase,
            local_name=local_name,
            on_status=self._set_status,
            on_sent=self._on_sent,
            on_received=self._on_received,
            on_close=self._on_close,
        )
        session.start()
        self.session = session

    def _require_passphrase(self) -> str:
        passphrase = self.pass_var.get()
        if not passphrase:
            raise ValueError("Shared passphrase is required.")
        return passphrase

    def _set_status(self, status: str) -> None:
        self.root.after(0, lambda: self.status_var.set(status))

    def _append_conversation(self, line: str) -> None:
        def update() -> None:
            self.conversation.configure(state="normal")
            self.conversation.insert("end", line + "\n")
            self.conversation.see("end")
            self.conversation.configure(state="disabled")

        self.root.after(0, update)

    def _on_sent(self, plaintext: str, ciphertext_b64: str) -> None:
        def update() -> None:
            self.sent_ciphertext.delete("1.0", "end")
            self.sent_ciphertext.insert("end", ciphertext_b64)

        self._append_conversation(f"{self.local_name}: {plaintext}")
        self.root.after(0, update)

    def _on_received(self, sender: str, ciphertext_b64: str, plaintext: str) -> None:
        def update() -> None:
            self.received_details.delete("1.0", "end")
            self.received_details.insert(
                "end",
                "Ciphertext:\n" + ciphertext_b64 + "\n\nPlaintext:\n" + plaintext,
            )

        self._append_conversation(f"{sender}: {plaintext}")
        self.root.after(0, update)

    def _on_close(self, reason: str) -> None:
        self.session = None
        self._set_status(f"Connection closed: {reason}")


def run_self_test() -> None:
    password = "correct horse battery staple"
    alice_salt = os.urandom(16)
    bob_salt = os.urandom(16)
    alice = CryptoContext(password, alice_salt, bob_salt)
    bob = CryptoContext(password, bob_salt, alice_salt)

    first = alice.encrypt("ok")
    second = alice.encrypt("ok")
    assert first.ciphertext != second.ciphertext, "Random IV should change repeated ciphertext."
    assert bob.decrypt(first) == "ok"
    assert bob.decrypt(second) == "ok"

    rekey_frame = alice.make_rekey_frame("Alice")
    bob.accept_rekey_frame(rekey_frame)
    assert alice.epoch == bob.epoch == 1
    secured = alice.encrypt("after rekey")
    assert bob.decrypt(secured) == "after rekey"

    tampered = EncryptedMessage(secured.epoch, secured.iv, secured.ciphertext[:-1] + b"\x00", secured.tag)
    try:
        bob.decrypt(tampered)
    except ValueError:
        pass
    else:
        raise AssertionError("Tampered ciphertext should fail HMAC verification.")

    print("Self-test passed: KDF, AES encryption, random IVs, HMAC, and rekeying work.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure P2P Messenger")
    parser.add_argument("--self-test", action="store_true", help="run crypto tests without opening the GUI")
    parser.add_argument("--tk-version", action="store_true", help="print the Tcl/Tk version used by this Python")
    args = parser.parse_args()
    if args.tk_version:
        interp = tk.Tcl()
        print(f"Tcl version: {interp.eval('info patchlevel')}")
        print(f"Tkinter TclVersion constant: {tk.TclVersion}")
        print(f"Tkinter TkVersion constant: {tk.TkVersion}")
        print(f"Python executable: {sys.executable}")
        return
    if args.self_test:
        run_self_test()
        return

    print(f"Starting Secure P2P Messenger {GUI_VERSION} from {os.path.abspath(__file__)}")
    root = tk.Tk()
    SecureMessengerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
