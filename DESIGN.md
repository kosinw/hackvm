### Description

> `hackvm` (hard)
> ---
> aka tim's reduced instruction set computer
>
> the flag format looks likes `hack{XXXXXXXXXXXXXX}`
>
> **Author**: kosinw
> 
> **Files:**
> * [hackvm.tar.gz](./handout/hackvm.tar.gz)
> * [online version]()
> 
> **Hints**:
> * passphrase matches `/[A-za-z0-9-]+/`
> * [`memcmp(3)`](https://man.freebsd.org/cgi/man.cgi?query=memcmp&sektion=3&apropos=0&manpath=NetBSD+7.0)

> `hackvm2` (insane)
> ---
> you might want to use an interactive debugger...
>
> the flag format looks like `hack{XXXXXXXXXXXXXX}`
> 
> **Author**: kosinw
> 
> **Files:**
> * [hackvm2.tar.gz](./handout/hackvm2.tar.gz)
> * [online version]()
> 
> **Hints**:
> * use z3 theorem prover

### Overview

The challenge name and description makes it pretty clear that it involves reverse engineering a RISC-V emulator.

The emulator is written in C and compiled as a stripped, static ELF binary with XOR-obfuscated stack strings. When run, the program will prompt the user for a password. It runs validation on the password, and then tells you the password is correct or not. The flag is the password.

The VM architecture is a single-core emulator for [RV32IM](https://en.wikipedia.org/wiki/RISC-V).

The CPU's memory is stored as a large array of 32-bit words. The CPU is little-endian. Like RV32IM, addresses can only be accessed on 32-bit word boundaries (otherwise a misaligned access fault triggers and the machine panics). There a total of 128MiB of RAM. When the CPU is initialized, the program specified in the args is loaded into memory starting from 0x80000000 (similar to qemu virt).

`hackvm` also implements a custom ABI for the `ecall` instruction that boils down to the following table:

```c
63	   => long read(unsigned int, char *, size_t);
64 	   => long write(unsigned int, char *, size_t);
93 	   => long exit(int);
0x1337 => long print_flag(const char *, unsigned int, const char*);
```

All other syscall numbers will cause no visible architectural state to change.

### Resources
- [RISC-V ISA Specification](https://github.com/riscv/riscv-isa-manual/releases/download/Ratified-IMAFDQC/riscv-spec-20191213.pdf)
- [RISC-V Reference Card](https://6191.mit.edu/_static/spring23/resources/references/6191_isa_reference.pdf)
- [Programming Linux Anti-Reversing Techniques](https://www.kneda.net/documentos/Programming%20Linux%20Anti-Reversing%20Techniques.pdf)
- [Bit Twiddling Hacks](http://graphics.stanford.edu/~seander/bithacks.html)
- [Linker Scripts](https://blog.thea.codes/the-most-thoroughly-commented-linker-script/)
- [xv6 for RISC-V](https://github.com/mit-pdos/xv6-riscv)