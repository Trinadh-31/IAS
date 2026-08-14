import math

def encrypt_caesar(plaintext: str, shift: int) -> str:
    res = []
    for ch in plaintext:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            res.append(ch)
    return ''.join(res)

def decrypt_caesar(ciphertext: str, shift: int) -> str:
    return encrypt_caesar(ciphertext, (-shift) % 26)

def _prepare_playfair_text(text: str) -> str:
    txt = ''.join([c for c in text.upper() if c.isalpha()])
    txt = txt.replace('J', 'I')
    res = ''
    i = 0
    while i < len(txt):
        a = txt[i]
        b = txt[i+1] if i+1 < len(txt) else 'X'
        if a == b:
            res += a + 'X'
            i += 1
        else:
            res += a + b
            i += 2
    if len(res) % 2 == 1:
        res += 'X'
    return res

def _build_playfair_matrix(key: str):
    key = ''.join([c for c in key.upper() if c.isalpha()])
    key = key.replace('J', 'I')
    seen = set()
    order = []
    for c in key:
        if c not in seen:
            seen.add(c)
            order.append(c)
    for c in map(chr, range(ord('A'), ord('Z')+1)):
        if c == 'J':
            continue
        if c not in seen:
            order.append(c)
            seen.add(c)
    matrix = [order[i*5:(i+1)*5] for i in range(5)]
    pos = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    return matrix, pos

def encrypt_playfair(plaintext: str, key: str) -> str:
    text = _prepare_playfair_text(plaintext)
    matrix, pos = _build_playfair_matrix(key)
    out = ''
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i+1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out += matrix[ra][(ca+1)%5] + matrix[rb][(cb+1)%5]
        elif ca == cb:
            out += matrix[(ra+1)%5][ca] + matrix[(rb+1)%5][cb]
        else:
            out += matrix[ra][cb] + matrix[rb][ca]
    return out

def decrypt_playfair(ciphertext: str, key: str) -> str:
    matrix, pos = _build_playfair_matrix(key)
    out = ''
    text = ''.join([c for c in ciphertext.upper() if c.isalpha()])
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i+1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out += matrix[ra][(ca-1)%5] + matrix[rb][(cb-1)%5]
        elif ca == cb:
            out += matrix[(ra-1)%5][ca] + matrix[(rb-1)%5][cb]
        else:
            out += matrix[ra][cb] + matrix[rb][ca]
    return out

# --- Simple SDES implementation (educational) ---
def _permute(bits, table):
    return [bits[i-1] for i in table]

def _bits_from_byte(b):
    return [(b >> i) & 1 for i in reversed(range(8))]

def _byte_from_bits(bits):
    b = 0
    for bit in bits:
        b = (b << 1) | (bit & 1)
    return b

def _left_shift(bits, n):
    return bits[n:] + bits[:n]

def _generate_sdes_subkeys(key10):
    # P10, P8
    p10 = [3,5,2,7,4,10,1,9,8,6]
    p8 = [6,3,7,4,8,5,10,9]
    k = _permute(key10, p10)
    left = k[:5]
    right = k[5:]
    left = _left_shift(left,1)
    right = _left_shift(right,1)
    k1 = _permute(left+right, p8)
    left = _left_shift(left,2)
    right = _left_shift(right,2)
    k2 = _permute(left+right, p8)
    return k1, k2

def _fk(bits8, subkey):
    # EP, S-boxes, P4
    EP = [4,1,2,3,2,3,4,1]
    S0 = [
        [1,0,3,2],
        [3,2,1,0],
        [0,2,1,3],
        [3,1,3,2]
    ]
    S1 = [
        [0,1,2,3],
        [2,0,1,3],
        [3,0,1,0],
        [2,1,0,3]
    ]
    P4 = [2,4,3,1]
    left = bits8[:4]
    right = bits8[4:]
    expanded = _permute(right, EP)
    xor = [a ^ b for a,b in zip(expanded, subkey)]
    a = xor[:4]
    b = xor[4:]
    row = (a[0]<<1) | a[3]
    col = (a[1]<<1) | a[2]
    s0 = S0[row][col]
    row = (b[0]<<1) | b[3]
    col = (b[1]<<1) | b[2]
    s1 = S1[row][col]
    bits4 = [ (s0>>1)&1, s0&1, (s1>>1)&1, s1&1 ]
    p4 = _permute(bits4, P4)
    left2 = [l ^ p for l,p in zip(left, p4)]
    return left2 + right

def sdes_encrypt_block(byte_in: int, key10_bits: list) -> int:
    # initial permutation IP
    IP = [2,6,3,1,4,8,5,7]
    IP_inv = [4,1,3,5,7,2,8,6]
    bits = _bits_from_byte(byte_in)
    bits = _permute(bits, IP)
    k1,k2 = _generate_sdes_subkeys(key10_bits)
    bits = _fk(bits, k1)
    # swap
    bits = bits[4:] + bits[:4]
    bits = _fk(bits, k2)
    bits = _permute(bits, IP_inv)
    return _byte_from_bits(bits)

def sdes_decrypt_block(byte_in: int, key10_bits: list) -> int:
    # reverse order of subkeys
    IP = [2,6,3,1,4,8,5,7]
    IP_inv = [4,1,3,5,7,2,8,6]
    bits = _bits_from_byte(byte_in)
    bits = _permute(bits, IP)
    k1,k2 = _generate_sdes_subkeys(key10_bits)
    bits = _fk(bits, k2)
    bits = bits[4:] + bits[:4]
    bits = _fk(bits, k1)
    bits = _permute(bits, IP_inv)
    return _byte_from_bits(bits)

def sdes_encrypt_bytes(data: bytes, key10: str) -> bytes:
    # key10 is string of '0'/'1' length 10
    if len(key10) != 10:
        raise ValueError('SDES key must be 10 bits')
    key_bits = [int(c) for c in key10]
    out = bytearray()
    for b in data:
        out.append(sdes_encrypt_block(b, key_bits))
    return bytes(out)

def sdes_decrypt_bytes(data: bytes, key10: str) -> bytes:
    if len(key10) != 10:
        raise ValueError('SDES key must be 10 bits')
    key_bits = [int(c) for c in key10]
    out = bytearray()
    for b in data:
        out.append(sdes_decrypt_block(b, key_bits))
    return bytes(out)

if __name__ == '__main__':
    # small self-test
    pt = 'HELLO'
    c = encrypt_caesar(pt, 3)
    assert decrypt_caesar(c, 3) == pt
    k = 'SECURE'
    pf = encrypt_playfair('HELLO WORLD', k)
    assert isinstance(pf, str)
    # SDES smoke
    key = '1010000010'
    data = b'ABC'
    e = sdes_encrypt_bytes(data, key)
    d = sdes_decrypt_bytes(e, key)
    assert d == data
