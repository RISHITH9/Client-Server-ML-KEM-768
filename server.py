import socket
import struct

import oqs
from cryptography.exceptions import InvalidTag
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

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        print("[SERVER] Waiting for one client...")

        connection, address = server_socket.accept()
        with connection:
            print(f"[SERVER] Connected by {address}")

            client_public_key = recv_frame(connection)
            print(f"[SERVER] Received public key ({len(client_public_key)} bytes)")

            with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(client_public_key)

            send_frame(connection, kem_ciphertext)
            print(f"[SERVER] Sent KEM ciphertext ({len(kem_ciphertext)} bytes)")

            aes_key = derive_aes_key(shared_secret)
            del shared_secret

            nonce = recv_frame(connection)
            encrypted_message = recv_frame(connection)
            if len(nonce) != 12:
                raise ValueError("AES-GCM nonce must be exactly 12 bytes.")

            try:
                plaintext = AESGCM(aes_key).decrypt(nonce, encrypted_message, None)
            except InvalidTag as exc:
                raise ValueError("AES-GCM authentication failed; message rejected.") from exc
            finally:
                del aes_key

            try:
                message = plaintext.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("Authenticated plaintext is not valid UTF-8.") from exc

            print("[SERVER] AES-GCM authentication succeeded")
            print("[SERVER] Decrypted message:")
            print(message)


if __name__ == "__main__":
    main()
