#!/usr/bin/env python3
from pwn import *

args = ['build/hackvm', '--trace', 'build/puzzle1']

def discover_password(length, initial_count):
    password = ['X']*length
    best_count = initial_count

    with log.progress("password") as l:
        for i in range(length):
            best_ch = 'X'

            for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-0123456789":
                password[i] = ch
                l.status(f"trying {''.join(password)}")
                
                count = 0
                context.log_level = 'error'
                p = process(args)

                buf = p.recvuntil(b'syscall=0x0000003f, a0=0x00000000, a1=0x87ffff2f, a2=0x00000001')
                count += len(buf)

                p.sendline("".join(password).encode())

                buf = p.recvall()
                count += len(buf)

                p.close()
                context.log_level = 'info'

                if count > best_count:
                    best_count = count
                    best_ch = ch
                    break
            
            password[i] = best_ch
    
    return "".join(password)

def discover_length():
    last_instcount = 0
    current_instcount = 0
    current_length = 1

    with log.progress("length") as l:
        while True:
            l.status(f"trying {current_length} {'X' * current_length}")

            context.log_level = 'error'
            p = process(args)

            buf = p.recvuntil(b'syscall=0x0000003f, a0=0x00000000, a1=0x87ffff2f, a2=0x00000001')
            current_instcount += len(buf)

            p.sendline(b'X' * current_length)

            buf = p.recvall()
            current_instcount += len(buf)

            p.close()
            context.log_level = 'info'

            if current_instcount < last_instcount:
                return current_length - 1, last_instcount
            else:
                last_instcount = current_instcount
                current_instcount = 0
                current_length += 1

length, count = discover_length()
password = discover_password(length, count)

log.info(password)