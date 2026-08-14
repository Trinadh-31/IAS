import socket
import json
from ciphers import (
    encrypt_caesar,
    decrypt_caesar,
    encrypt_playfair,
    decrypt_playfair,
    sdes_encrypt_bytes,
    sdes_decrypt_bytes,
)

HOST = '127.0.0.1'
PORT = 9000

def recv_all(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed')
        buf += chunk
    return buf

def send_header_and_payload(conn, header: dict, payload: bytes):
    hdr_b = json.dumps(header).encode()
    conn.send(len(hdr_b).to_bytes(4,'big'))
    conn.send(hdr_b)
    if payload:
        conn.send(payload)

def interactive():
    print('Algorithms: 1) Caesar 2) Playfair 3) SDES')
    while True:
        print('\nChoose action:')
        print('1) Send message')
        print('2) Send 1MB file (SDES)')
        print('3) Quit')
        choice = input('> ').strip()
        if choice == '1':
            alg_choice = input('Pick algorithm (1 Caesar,2 Playfair,3 SDES): ').strip()
            if alg_choice == '1':
                alg='caesar'
                shift = int(input('Enter integer shift key (e.g., 3): '))
                plaintext = input('Message to send: ')
                cipher = encrypt_caesar(plaintext, shift)
                print('Encrypted message (ciphertext):', cipher)
                payload = cipher.encode('utf-8')
                header = {'mode':'message','algorithm':alg,'key':str(shift),'payload_size':len(payload)}
            elif alg_choice == '2':
                alg='playfair'
                key = input('Enter playfair keyword: ')
                plaintext = input('Message to send: ')
                cipher = encrypt_playfair(plaintext, key)
                print('Encrypted message (ciphertext):', cipher)
                payload = cipher.encode('utf-8')
                header = {'mode':'message','algorithm':alg,'key':key,'payload_size':len(payload)}
            elif alg_choice == '3':
                alg='sdes'
                key = input('Enter 10-bit SDES key (e.g., 1010000010): ')
                plaintext = input('Message to send: ')
                plain_bytes = plaintext.encode('utf-8')
                cipher_bytes = sdes_encrypt_bytes(plain_bytes, key)
                print('Encrypted message (hex):', cipher_bytes.hex())
                payload = cipher_bytes
                header = {'mode':'message','algorithm':alg,'key':key,'payload_size':len(payload)}
            else:
                print('Invalid')
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                send_header_and_payload(s, header, payload)
                # wait reply
                try:
                    hdr_len_b = recv_all(s, 4)
                    hdr_len = int.from_bytes(hdr_len_b, 'big')
                    hdr = json.loads(recv_all(s, hdr_len).decode())
                    payload_size = hdr.get('payload_size',0)
                    payload = recv_all(s, payload_size) if payload_size>0 else b''
                    print('\n--- Server reply received ---')
                    if hdr.get('mode') == 'message':
                        alg = hdr.get('algorithm')
                        key = hdr.get('key')
                        if alg == 'caesar':
                            cipher_text = payload.decode('utf-8')
                            plain = decrypt_caesar(cipher_text, int(key))
                            print('Ciphertext (server->client):', cipher_text)
                            print('Plaintext:', plain)
                        elif alg == 'playfair':
                            cipher_text = payload.decode('utf-8')
                            plain = decrypt_playfair(cipher_text, key)
                            print('Ciphertext (server->client):', cipher_text)
                            print('Plaintext:', plain)
                        elif alg == 'sdes':
                            cipher_bytes = payload
                            plain_bytes = sdes_decrypt_bytes(cipher_bytes, key)
                            print('Ciphertext (hex):', cipher_bytes[:200].hex())
                            print('Plaintext (bytes):', plain_bytes[:200])
                    elif hdr.get('mode') == 'file':
                        print('Server sent a file back; use receive logic')
                except Exception as e:
                    print('No reply or failed to parse reply', e)

        elif choice == '2':
            # send 1MB file using SDES
            alg='sdes'
            key = input('Enter 10-bit SDES key to use: ')
            fname = 'sample_1mb.bin'
            try:
                with open(fname,'rb') as f:
                    data = f.read()
            except FileNotFoundError:
                print('1MB sample not found. Run make_files.py to generate sample_1mb.bin')
                continue
            cipher = sdes_encrypt_bytes(data, key)
            print('Encrypted 1MB file preview (hex, first 200 bytes):', cipher[:200].hex())
            header = {'mode':'file','algorithm':'sdes','key':key,'filename':fname,'payload_size':len(cipher)}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                send_header_and_payload(s, header, cipher)
                # expect server to send back a 10KB file
                try:
                    hdr_len_b = recv_all(s, 4)
                    hdr_len = int.from_bytes(hdr_len_b, 'big')
                    hdr = json.loads(recv_all(s, hdr_len).decode())
                    payload_size = hdr.get('payload_size',0)
                    payload = recv_all(s, payload_size) if payload_size>0 else b''
                    print('Received file header from server:', hdr)
                    if hdr.get('algorithm') == 'sdes':
                        plain = sdes_decrypt_bytes(payload, hdr.get('key'))
                        outname = 'server_sent_'+hdr.get('filename','file.bin')
                        with open(outname,'wb') as f:
                            f.write(plain)
                        print('Saved decrypted file from server to', outname)
                        print('Preview (first 200 bytes):', plain[:200])
                except Exception as e:
                    print('No file reply or failed to parse', e)

        elif choice == '3':
            break
        else:
            print('Invalid')

if __name__ == '__main__':
    interactive()
