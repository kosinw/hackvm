#!/usr/bin/env python3
from pwn import *
import tempfile
import os

def spawn():
    f = tempfile.TemporaryFile('wb')
    args = ['build/hackvm', '--trace', 'build/puzzle1']
    p = process(args, stderr=f)
    return p, f

def assemble(arr):
    return "".join(arr)

def get_side_channel_leakage(payload):
    context.log_level = 'error'
    p, f = spawn()
    p.recvuntil(b"please enter the passphrase: ")
    p.sendline(payload.encode())
    p.recvall()
    p.close()
    context.log_level = 'info'
    w = os.fstat(f.fileno()).st_size
    f.close()

    return w

def discover_password(length):
    payload = ["X"]*length
    best = get_side_channel_leakage(assemble(payload))

    with log.progress("Finding password contents") as l:
        for i in range(length):
            for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_0123456789":
                payload[i] = ch
                l.status(f"trying {assemble(payload)}")
                nbytes = get_side_channel_leakage(assemble(payload))

                if nbytes > best:
                    best = nbytes
                    break
    
    return assemble(payload)

def discover_length():
    best = 0
    payload = ["X"]

    with log.progress("Finding password length") as l:
        while True:
            l.status(f"trying {assemble(payload)}")
            nbytes = get_side_channel_leakage(assemble(payload))

            if nbytes < best:
                N = len(payload) - 1
                l.success(f"{N}")
                return N
            else:
                payload.append("X")
                best = nbytes


if __name__ == "__main__":
    password_length = discover_length()
    password = discover_password(password_length)
    log.info(f"password={password}")

    p = process(['build/hackvm', 'build/puzzle1'])
    p.interactive()    