import os
import socket
import struct

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = "127.0.0.1"
PORT = 5000
KEM_ALGORITHM = "ML-KEM-768"
MAX_FRAME_SIZE = 1024 * 1024


def recv_exact(sock, size):
    """Read exactly size bytes from a TCP socket or fail on disconnect."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Peer disconnected unexpectedly.")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock, payload):
    """Send one frame: a 4-byte network-order length and its payload."""
    if not payload or len(payload) > MAX_FRAME_SIZE:
        raise ValueError("Payload size is outside the allowed frame range.")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock):
    """Receive and validate one length-prefixed frame."""
    length_bytes = recv_exact(sock, 4)
    message_length = struct.unpack("!I", length_bytes)[0]
    if message_length == 0 or message_length > MAX_FRAME_SIZE:
        raise ValueError("Invalid frame length.")
    return recv_exact(sock, message_length)


def derive_aes_key(shared_secret):
    """Derive a 256-bit AES key from the KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pqc-mlkem-demo-aes-gcm",
    ).derive(shared_secret)


def main():
    enabled_kems = oqs.get_enabled_kem_mechanisms()
    if KEM_ALGORITHM not in enabled_kems:
        raise RuntimeError(f"{KEM_ALGORITHM} is unavailable in this liboqs build.")

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        print(f"[CLIENT] Generated ML-KEM public key ({len(public_key)} bytes)")

        # Keep the TCP connection open across the whole KEM and message exchange.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            print(f"[CLIENT] Connecting to {HOST}:{PORT}...")
            client_socket.connect((HOST, PORT))
            print("[CLIENT] Connected")

            send_frame(client_socket, public_key)
            print("[CLIENT] Sent public key")

            kem_ciphertext = recv_frame(client_socket)
            print(f"[CLIENT] Received KEM ciphertext ({len(kem_ciphertext)} bytes)")

            shared_secret = kem.decap_secret(kem_ciphertext)
            aes_key = derive_aes_key(shared_secret)
            del shared_secret
            print("[CLIENT] Derived AES key; secret material is not displayed")

            message = input("[CLIENT] Enter a message to send: ")
            plaintext = message.encode("utf-8")
            if not plaintext:
                raise ValueError("The message must not be empty.")

            nonce = os.urandom(12)
            encrypted_message = AESGCM(aes_key).encrypt(nonce, plaintext, None)
            del aes_key

            send_frame(client_socket, nonce)
            send_frame(client_socket, encrypted_message)
            print("[CLIENT] Sent AES-GCM protected message")

    print("[CLIENT] Finished")


if __name__ == "__main__":
    main()
