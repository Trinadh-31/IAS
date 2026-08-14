Python Client-Server Ciphers Demo

Files:
- `ciphers.py` : Implements Caesar, Playfair, and a simple educational SDES (byte-wise).
- `server.py` : TCP server that receives header+payload, displays ciphertext and decrypted plaintext, and replies.
- `client.py` : Interactive client. Choose algorithm, send messages or 1MB SDES file.
- `make_files.py` : Creates `sample_1mb.bin` and `sample_10kb.bin` used for SDES file transfers.

Quick start:

1. Generate sample files:

```bash
python make_files.py
```

2. Start the server (in one terminal):

```bash
python server.py
```

3. Run the client (in another terminal):

```bash
python client.py
```

Follow interactive prompts. For SDES key use a 10-bit string like `1010000010`.

Notes:
- The SDES implementation is educational and works byte-by-byte in ECB mode.
- For large files the client and server write received decrypted files to disk (`decrypted_<filename>` or `server_sent_<filename>`).
