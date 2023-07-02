#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from dataclasses import dataclass
import subprocess
import ctypes

KEY  = b"hack{5olv1ng_sy5t3ms_of_c0n5tra1nt5_f0r_fun_4nd_pr0f1t_08111996}"
FLAG = b"cfe1dd0d044f525180bb3cb11f8fa9b2e5dc59408cba908ea0e807980202b82"

@dataclass
class Constraint:
    pass

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

def assemble(assembly_code):
    command = f'rasm2 -a riscv -b 32 -f - << EOF\n{assembly_code}\nEOF'
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
    machine_code = bytes.fromhex(result.stdout.strip())
    return machine_code

# stepN(char *password)
assembly = """
step0:
    xor ra, sp, gp
    add tp, ra, sp
    beq ra, tp, good
bad:
    mv a0, 1
    addi x0, x0, 0
good:
    ret
end0:
"""

print(assemble(assembly))