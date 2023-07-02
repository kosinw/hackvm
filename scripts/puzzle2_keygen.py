#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

KEY     = b"hack{5olv1ng_sy5t3ms_of_c0n5tra1nt5_f0r_fun_4nd_pr0f1t_08111996}"
FLAG    = b"0cfe1dd0d044f525180bb3cb11f8fa9b2e5dc59408cba908ea0e807980202b82"

def generate_ciphertext():
    H = SHA256.new()
    H.update(KEY)
    k = H.digest()
    iv = get_random_bytes(16)
    cipher = AES.new(k, AES.MODE_CTR, initial_value=iv, nonce=b'')
    ciphertext = cipher.encrypt(FLAG)
    return iv, ciphertext, k

def c_array(r):
    return f"{{{ ', '.join([hex(i) for i in r]) }}}"

iv, ciphertext, key = generate_ciphertext()
print(f"key: {key.hex()}\nciphertext: {ciphertext.hex()}\niv: {iv.hex()}")
print(f"const char ciphertext[] = {c_array(iv + ciphertext)};")
print(f"#define KEY_LEN {len(KEY)}")