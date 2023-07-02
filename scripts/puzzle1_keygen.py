#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pwn import *
import ctypes

context.endian = 'little'
context.signed = 'unsigned'

KEY  = b"hack{in5tructi0n_s3ts_w4nt_t0_b3_fr33_18052010}"
FLAG = b"076202dc7bf6cd3fafe1fbcaba89cad47b225ffda5261b70b41960f7d67dd6f7"

def murmur_scramble(k):
    k = ctypes.c_uint32(0xcc9e2d51 * k).value
    k = ctypes.c_uint32((k << 15) | (k >> 17)).value
    k = ctypes.c_uint32(0x1b873593 * k).value
    return k

def murmur3(key, seed):
    l = len(key)
    h = ctypes.c_uint32(seed).value
    k = 0
    i = l >> 2

    while i != 0:
        k = u32(key[0:4])
        key = key[4:]
        h = ctypes.c_uint32(h ^ murmur_scramble(k)).value
        h = ctypes.c_uint32((h << 13) | (h >> 19)).value
        h = ctypes.c_uint32(h * 5 +  0xe6546b64).value
        i -= 1

    k = 0
    i = l & 3

    while i != 0:
        k = ctypes.c_uint32(k << 8).value
        k = ctypes.c_uint32(k | u8(key[i - 1:i])).value
        i -= 1

    h = ctypes.c_uint32(h ^ murmur_scramble(k)).value
    h = h ^ l
    h = h ^ (h >> 16)
    h = ctypes.c_uint32(h * 0x85ebca6b).value
    h = h ^ (h >> 13)
    h = ctypes.c_uint32(h * 0xc2b2ae35).value
    h = h ^ (h >> 16)
    return ctypes.c_uint32(h).value

def seed_xorshift():
    global x0, x1
    x0 = 0xa9662f37ce8d7c2
    x1 = 0x2dc85cbda48610b

def xorshift128p():
    global x0, x1
    t = ctypes.c_uint64(x0).value
    s = ctypes.c_uint64(x1).value
    x0 = s
    t = ctypes.c_uint64(t ^ (t << 23)).value
    t = ctypes.c_uint64(t ^ (t >> 18)).value
    t = ctypes.c_uint64(t ^ (s ^ (s >> 5))).value
    x1 = t
    return ctypes.c_uint32(t + s).value

def hash_password_key():
    seed_xorshift()
    result = bytearray()

    for i in range(len(KEY)):
        a = murmur3(KEY[i:i+1], xorshift128p())
        b = murmur3(p32(a), xorshift128p())
        c = (a ^ b ^ xorshift128p())
        d = ctypes.c_uint32(ctypes.c_uint64(c * 0xe984385).value >> 11).value
        e = ctypes.c_uint32((d << 14) | (d >> 18)).value
        result.extend(p32(e))

    return result

def encrypt_flag():
    H = SHA256.new()
    H.update(KEY)
    hash = H.digest()

    iv = get_random_bytes(16)
    cipher = AES.new(hash, AES.MODE_CTR, initial_value=iv, nonce=b'')
    ciphertext = cipher.encrypt(FLAG)
    return iv, ciphertext, hash

def c_array(r):
    return f"{{{ ', '.join([hex(i) for i in r]) }}}"

result = hash_password_key()
iv, ciphertext, key = encrypt_flag()
print(f"key: {key.hex()}\nciphertext: {ciphertext.hex()}\niv: {iv.hex()}")
print(f"const char password[] = {c_array(result)};")
print(f"const char ciphertext[] = {c_array(iv + ciphertext)};")
print("")
print(f"#define KEY_LEN {len(KEY)}")