#!/usr/bin/env python3
from dataclasses import dataclass, field
from enum import Enum, auto
from z3 import *
from itertools import count, cycle
from textwrap import dedent
import sys
import random
import tempfile
import os
import subprocess
import struct

KEY             = b"hack{5olv1ng_sy5t3ms_of_c0n5tra1nt5_f0r_fun_4nd_pr0f1t_08111996}"
LEN             = len(KEY)
NUM_CONSTRAINTS = 128
KEY_Z3          = [BitVec(f'c{i:02}', 8) for i in range(LEN)]
SEED            = 0x34f569d2338291f3

def generate_indices():
    s = range(LEN)
    s = list(s)

    while True:
        random.shuffle(s)
        for i in s:
            yield i

def next_pair(generator):
    a = next(generator)
    while (b := next(generator)) == a:
        pass
    return a, b

class ConstraintKind(Enum):
    ADD    = auto()
    SUB    = auto()
    XOR    = auto()
    AND    = auto()
    OR     = auto()

@dataclass
class Constraint:
    kind: ConstraintKind
    arg1: int
    arg2: int
    magic: int
    id: int = field(default_factory=count().__next__)

    def _label(self, suffix=None):
        if suffix is None:
            return f"constraint{self.id:03}"
        else:
            return f"constraint{self.id:03}{suffix}"

    def to_shellcode(self):
        return dedent(self._to_shellcode()) + "\n" + dedent(self._footer())

    def _footer(self):
        return f"""\
                {self._label('.L6')}:
                    li      a4,0x{self.magic:08x}
                {self._label('.L3')}:
                    addi    a1,a1,4
                    lw      a5,0(a1)
                    xor     a3,a5,a4
                    sw      a3,0(a1)
                    bne     a5,a4,{self._label('.L3')}
                    addi    a2,a2,4
                    jr      a2
                    .word   0"""

    def _to_shellcode(self):
        a, b = self.arg1, self.arg2

        match self.kind:
            case ConstraintKind.ADD:
                return f"""\
                    {self._label()}:
                        lbu     a5,{a}(a0)
                        lbu     a3,{b}(a0)
                        li      a4,{KEY[a] + KEY[b]}
                        add     a5,a5,a3
                        beq     a5,a4,{self._label('.L6')}
                        li      a7, 93
                        ecall"""
            case ConstraintKind.SUB:
                if KEY[a] < KEY[b]: b, a = a, b
                return f"""\
                    {self._label()}:
                        lbu     a5,{a}(a0)
                        lbu     a3,{b}(a0)
                        li      a4,{KEY[a] - KEY[b]}
                        sub     a5,a5,a3
                        beq     a5,a4,{self._label('.L6')}
                        li      a7, 93
                        ecall"""
            case ConstraintKind.XOR:
                return f"""\
                    {self._label()}:
                        lbu     a5,{a}(a0)
                        lbu     a3,{b}(a0)
                        li      a4,{KEY[a] ^ KEY[b]}
                        xor     a5,a5,a3
                        beq     a5,a4,{self._label('.L6')}
                        li      a7, 93
                        ecall"""
            case ConstraintKind.AND:
                return f"""\
                    {self._label()}:
                        lbu     a5,{a}(a0)
                        lbu     a3,{b}(a0)
                        li      a4,{KEY[a] & KEY[b]}
                        and     a5,a5,a3
                        beq     a5,a4,{self._label('.L6')}
                        li      a7, 93
                        ecall"""
            case ConstraintKind.OR:
                return f"""\
                    {self._label()}:
                        lbu     a5,{a}(a0)
                        lbu     a3,{b}(a0)
                        li      a4,{KEY[a] | KEY[b]}
                        or      a5,a5,a3
                        beq     a5,a4,{self._label('.L6')}
                        li      a7, 93
                        ecall"""

    def to_z3(self):
        a, b = self.arg1, self.arg2

        match self.kind:
            case ConstraintKind.ADD:
                return KEY_Z3[a] + KEY_Z3[b] == KEY[a] + KEY[b]
            case ConstraintKind.SUB:
                if KEY[a] < KEY[b]:
                    b, a = a, b
                return KEY_Z3[a] - KEY_Z3[b] == KEY[a] - KEY[b]
            case ConstraintKind.XOR:
                return KEY_Z3[a] ^ KEY_Z3[b] == KEY[a] ^ KEY[b]
            case ConstraintKind.AND:
                return KEY_Z3[a] & KEY_Z3[b] == KEY[a] & KEY[b]
            case ConstraintKind.OR:
                return KEY_Z3[a] | KEY_Z3[b] == KEY[a] | KEY[b]

def generate_conditions():
    g = generate_indices()
    opts = list(ConstraintKind)
    result = []

    for _ in range(NUM_CONSTRAINTS):
        a, b = next_pair(g)
        kind = random.choice(opts)
        result.append(Constraint(kind, a, b, random.getrandbits(32)))

    return result

def model_constraints(conds):
    # make sure each character is within ascii range
    s = Solver()

    for i in range(LEN):
        s.add(KEY_Z3[i] > 0x20)
        s.add(KEY_Z3[i] < 0x7f)

    for cond in conds:
        s.add(cond.to_z3())

    return s

def check_soundness(s):
    # this should obviously be sat so its solvable
    assert s.check() == z3.sat, 'gen not sat'

    # this should be unsat since there are no other solutions
    s.add(Or(*(KEY_Z3[i] != v for i, v in enumerate(KEY))))
    assert s.check() == z3.unsat, 'gen not fully constrained'

def test_solve(conds):
    s = Solver()

    for i in range(LEN):
        s.add(KEY_Z3[i] > 0x20)
        s.add(KEY_Z3[i] < 0x7f)

    for cond in conds:
        s.add(cond.to_z3())

    assert s.check() == z3.sat, 'gen not sat'

    m = s.model()
    result = bytes(m[c].as_long() for c in KEY_Z3)
    return result

def assemble(s):
    # Create a temporary directory to store the assembly and binary files
    s = f".text\n.globl _start\n_start:\n{s}\n"
    with tempfile.TemporaryDirectory() as temp_dir:
        assembly_file = os.path.join(temp_dir, 'program.s')
        elf_file = os.path.join(temp_dir, 'program.elf')
        binary_file = os.path.join(temp_dir, 'program.bin')

        # Write the assembly code to the temporary file
        with open(assembly_file, 'w') as file:
            file.write(s)

        # Assemble the program and capture the output
        command = [
            'riscv32-unknown-elf-gcc',
            '-nostdlib',
            '-nostartfiles',
            '-march=rv32im',
            '-mabi=ilp32',
            '-Wl,-Ttext=0',
            '-o', elf_file,
            assembly_file
        ]
        subprocess.run(command, check=True)
        command = [
            'riscv32-unknown-elf-objcopy',
            '-O', 'binary',
            elf_file,
            binary_file
        ]
        subprocess.run(command, check=True)

        # Read the assembled binary file
        with open(binary_file, 'rb') as file:
            assembled_program = file.read()
    return assembled_program

def xor_cipher(text, key):
    K = cycle(struct.pack("<I", key))
    result = bytearray()

    for a, b in zip(text, K):
        result.append(a ^ b)

    assert len(result) == len(text)
    return result

def generate_assembly(conds):
    parts = []
    for cond in conds:
        parts.append(assemble(cond.to_shellcode()))
    parts.append(assemble("ret\n.word 0"))
    for i in range(NUM_CONSTRAINTS):
        parts[i + 1] = xor_cipher(parts[i + 1], conds[i].magic)
    return b"".join(parts)

def c_array(r):
    return f"{{{ ', '.join([ f'0x{i:02x}' for i in r ]) }}}"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        exit()

    random.seed(SEED)

    conds = generate_conditions()

    # model the constraints in z3 and make sure its actually solvable
    s = model_constraints(conds)
    check_soundness(s)

    # put constraints into a file
    with open(sys.argv[1], 'w') as f:
        for c in conds:
            f.write(f"{c.to_z3()}, magic={c.magic:08x}\n")

    # try doing a test solve
    result = test_solve(conds)
    assert result == KEY, 'test key is wrong'

    # generate assembly based on constraints
    shellcode = generate_assembly(conds)

    with open(sys.argv[2], 'w') as f:
        f.write(f'__attribute__((section(".data.crypto"))) char code[] = {c_array(shellcode)};')