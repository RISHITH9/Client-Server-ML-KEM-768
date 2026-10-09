# Client-Server ML-KEM-768 Demo

An educational Python client-server demonstration of post-quantum key establishment with **ML-KEM-768**, followed by message encryption and authentication with **AES-256-GCM**.

> [!WARNING]
> **Educational prototype only — not production-ready.** This is a learning example, not a reviewed secure messaging protocol. It does not authenticate the client or server, uses custom TCP framing, and has not undergone a security audit. Do not use it to protect sensitive or production data. Open Quantum Safe's `liboqs` is intended for prototyping and experimentation; consult its current security guidance and use reviewed, supported protocols and implementations for real deployments.

## What it demonstrates

- ML-KEM-768 key generation, encapsulation, and decapsulation via `liboqs-python`.
- Derivation of an AES key from the KEM shared secret with HKDF-SHA-256.
- AES-GCM authenticated encryption of one client-to-server text message.
- Length-prefixed message framing over a local TCP connection.

ML-KEM is a **key-encapsulation mechanism**, not a message-encryption algorithm. In this demo the client creates a KEM key pair and sends its public key to the server. The server encapsulates to that public key, then returns the KEM ciphertext. The client decapsulates it. Both sides derive the same shared secret. The client then encrypts a message with AES-GCM and sends the nonce and ciphertext; the server authenticates and decrypts it.

## Protocol flow

```text
Client                                      Server
  |                                            |
  |--- ML-KEM-768 public key ----------------->|
  |                                            | encapsulate(public key)
  |<-- ML-KEM ciphertext ----------------------|
  | decapsulate(ciphertext)                    |
  |                                            |
  | Both derive the same 32-byte KEM secret    |
  | Both derive a 32-byte AES key using HKDF   |
  |                                            |
  |--- 12-byte nonce ------------------------->|
  |--- AES-GCM ciphertext + tag -------------->|
  |                                            | authenticate + decrypt
```

**Role direction:** the client owns the KEM key pair in this particular example. Another common design has the server own the key pair and the client encapsulate to the server's public key; the KEM operations can be arranged either way, provided the public/private-key owner performs decapsulation.

## ML-KEM-768 sizes

The values below are byte lengths defined for ML-KEM-768 and observed in the demonstration:

| Object | Size | Handling |
| --- | ---: | --- |
| Encapsulation (public) key | 1,184 bytes | Sent by client to server |
| Decapsulation (private) key | 2,400 bytes | Retained inside the client's KEM context; never transmitted |
| KEM ciphertext | 1,088 bytes | Sent by server to client |
| KEM shared secret | 32 bytes | Derived independently on both sides; must remain secret |
| HKDF output / AES-256 key | 32 bytes | Used by AES-GCM; never transmit or log |
| AES-GCM nonce | 12 bytes | Sent with ciphertext; not secret; must not repeat for the same key |
| AES-GCM authentication tag | 16 bytes | Appended to ciphertext by the `cryptography` AESGCM API |

The ML-KEM security category is a property of the standardized parameter set; it should not be read as the number of bits in the key or equated directly to AES key length.

## Requirements

- Python 3.10 or later (tested in a virtual environment; package compatibility depends on platform).
- A working C build toolchain may be needed if `liboqs-python` builds or loads its underlying `liboqs` dependency from source.
- `liboqs-python` with ML-KEM-768 enabled.
- `cryptography`.

The wrapper and native library have platform and version constraints. If installation fails, consult the upstream `liboqs-python` installation instructions and avoid mixing multiple Python environments.

## Setup

Create and activate a virtual environment from the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

Check that the Python wrapper can import and ML-KEM-768 is enabled:

```bash
python -c "import oqs; print('ML-KEM-768 enabled:', 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms())"
```

The output should report `True`. An `oqs` module import does not necessarily provide an `oqs.__version__` attribute; use the enabled-mechanism check instead.

## Run locally

Open two terminals in the project directory and activate the same virtual environment in each.

Terminal 1 — start the server:

```bash
python server.py
```

Terminal 2 — run the client:

```bash
python client.py
```

Enter a message at the client prompt. The server should report that it authenticated and decrypted the message. The server handles one client connection and then exits; restart it before another run.

Both programs bind/connect to `127.0.0.1:5000`, so this is intended for a same-machine demo. Do not expose the unauthenticated demo server to a network.

## Message framing

TCP is a byte stream and does not preserve application message boundaries. Each application frame in this demo consists of a four-byte unsigned, big-endian payload length followed by exactly that many payload bytes. The code reads the length and then loops until it receives the full payload. This framing is a small teaching aid, not a hardened network protocol; the sample applies a maximum-frame-size check before allocating/reading data.

The message exchange uses three frames after KEM setup: nonce, AES-GCM ciphertext with its appended tag, and no separate tag frame. AES-GCM verification fails if the key, nonce, ciphertext, or tag is incorrect or altered.

## Key derivation and nonce

Both sides apply HKDF-SHA-256 to the 32-byte ML-KEM shared secret with the same context string (`pqc-mlkem-demo-aes-gcm`) to derive a 32-byte AES key. HKDF does not add entropy; it derives a key for the symmetric algorithm from the KEM secret.

The client generates a fresh 12-byte nonce with `os.urandom()` for each encryption and sends it alongside the ciphertext. A nonce is not a secret, but it must never be reused with the same AES-GCM key. The demo establishes a new KEM key/secret for each connection; do not reuse a key/nonce scheme outside this example without a proper protocol design.

## Security limitations

This project intentionally omits important requirements for a real secure channel:

- **No authentication:** ML-KEM alone does not prove who owns a public key. An active attacker could substitute keys or establish separate sessions. Real systems need authenticated key exchange and identity validation.
- **No TLS or established protocol:** custom socket code does not provide the security engineering, negotiation, downgrade resistance, rekeying, or interoperability of a reviewed protocol.
- **Prototype dependency:** `liboqs` and its language wrappers are intended for prototyping and evaluation; check upstream guidance for current status and use of standardized algorithms.
- **Limited error handling and denial-of-service defenses:** this is a small demonstration, not hardened server software.
- **No persistence, replay protection, or multi-message session design:** it encrypts a single message per server run.
- **No formal verification or audit:** successful local execution only shows that this particular round trip worked; it is not evidence of production security.

For production communications, use a vetted, authenticated protocol and maintained cryptographic libraries, follow the relevant standards and implementation guidance, and obtain expert review. Do not design a custom cryptographic protocol from this example.

## Files

- `client.py` — generates the ML-KEM key pair, performs decapsulation, derives an AES key, and sends one encrypted message.
- `server.py` — encapsulates to the client's public key, derives the AES key, and decrypts/authenticates the message.
- `requirements.txt` — Python package dependencies.
- `.gitignore` — excludes local environments and sensitive/local files.

## License

No license is currently specified. Unless a license is added, others do not receive an explicit license to reuse, modify, or distribute this project's code. Add a license only after choosing the terms you want.
