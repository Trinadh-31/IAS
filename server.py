import socket
import json
import os
from ciphers import (
    decrypt_caesar,
    decrypt_playfair,
    sdes_decrypt_bytes,
    encrypt_caesar,
    encrypt_playfair,
    sdes_encrypt_bytes,
)

HOST = '0.0.0.0'
PORT = 9000

def recv_all(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed')
        buf += chunk
    return buf

def handle_connection(conn, addr):
    print('Client connected', addr)
    try:
        # read header length
        hdr_len_b = recv_all(conn, 4)
        hdr_len = int.from_bytes(hdr_len_b, 'big')
        hdr = json.loads(recv_all(conn, hdr_len).decode())
        payload_size = hdr.get('payload_size', 0)
        payload = recv_all(conn, payload_size) if payload_size > 0 else b''

        mode = hdr.get('mode')
        alg = hdr.get('algorithm')
        key = hdr.get('key')

        print(f"Received mode={mode} algorithm={alg} key={key} size={payload_size}")

        if mode == 'message':
            if alg == 'caesar':
                cipher_text = payload.decode('utf-8')
                plain = decrypt_caesar(cipher_text, int(key))
                print('Ciphertext (client->server):', cipher_text)
                print('Decrypted plaintext:', plain)
            elif alg == 'playfair':
                cipher_text = payload.decode('utf-8')
                plain = decrypt_playfair(cipher_text, key)
                print('Ciphertext (client->server):', cipher_text)
                print('Decrypted plaintext:', plain)
            elif alg == 'sdes':
                cipher_bytes = payload
                plain_bytes = sdes_decrypt_bytes(cipher_bytes, key)
                print('Received SDES ciphertext (hex, first 200 bytes):', cipher_bytes[:200].hex())
                print('Decrypted plaintext (first 200 bytes):', plain_bytes[:200])
            else:
                print('Unknown algorithm')

            # send a reply using same algorithm/key
            if alg in ('caesar','playfair'):
                reply_plain = f"Server reply: received your message"
                if alg == 'caesar':
                    reply_cipher = encrypt_caesar(reply_plain, int(key))
                else:
                    reply_cipher = encrypt_playfair(reply_plain, key)
                reply_payload = reply_cipher.encode('utf-8')
                hdr = {'mode':'message','algorithm':alg,'key':key,'payload_size':len(reply_payload)}
                hdr_b = json.dumps(hdr).encode()
                conn.send(len(hdr_b).to_bytes(4,'big'))
                conn.send(hdr_b)
                conn.send(reply_payload)
                print('Sent reply ciphertext and plaintext shown above (server side)')
            elif alg == 'sdes':
                # send a 10KB file (pre-created by make_files.py)
                fname = 'sample_10kb.bin'
                if not os.path.exists(fname):
                    print('10KB sample not found on server; creating small placeholder')
                    with open(fname,'wb') as f:
                        f.write(os.urandom(10*1024))
                with open(fname,'rb') as f:
                    data = f.read()
                cipher = sdes_encrypt_bytes(data, key)
                print('Server will send SDES-encrypted 10KB file back to client')
                hdr = {'mode':'file','algorithm':'sdes','key':key,'filename':fname,'payload_size':len(cipher)}
                hdr_b = json.dumps(hdr).encode()
                conn.send(len(hdr_b).to_bytes(4,'big'))
                conn.send(hdr_b)
                conn.send(cipher)
                print('Sent encrypted 10KB file to client; server displays plaintext preview:')
                print(data[:200])
        elif mode == 'file':
            # save incoming file; assume SDES
            fname = hdr.get('filename','received.bin')
            alg = hdr.get('algorithm')
            key = hdr.get('key')
            print('Saving incoming file to', fname)
            with open('received_'+fname,'wb') as f:
                f.write(payload)
            if alg == 'sdes':
                plain = sdes_decrypt_bytes(payload, key)
                with open('decrypted_'+fname,'wb') as f:
                    f.write(plain)
                print('Saved cipher preview (hex):', payload[:200].hex())
                print('Saved decrypted preview (first 200 bytes):', plain[:200])
            else:
                print('Received non-SDES file; saved as-is')
            # after receiving file, also send 10KB file back if desired
            # we'll send sample_10kb.bin
            send_fname = 'sample_10kb.bin'
            if not os.path.exists(send_fname):
                with open(send_fname,'wb') as f:
                    f.write(os.urandom(10*1024))
            with open(send_fname,'rb') as f:
                data = f.read()
            cipher = sdes_encrypt_bytes(data, key)
            hdr2 = {'mode':'file','algorithm':'sdes','key':key,'filename':send_fname,'payload_size':len(cipher)}
            hdr_b = json.dumps(hdr2).encode()
            conn.send(len(hdr_b).to_bytes(4,'big'))
            conn.send(hdr_b)
            conn.send(cipher)
            print('Sent encrypted 10KB file back to client')
        else:
            print('Unknown mode')
    except Exception as e:
        print('Connection handling failed:', e)
    finally:
        conn.close()

def main():
    print('Starting server on', HOST, PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == '__main__':
    main()
