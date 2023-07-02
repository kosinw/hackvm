/*********************************************************************
* Filename:   vm.c
* Author:     Kosi Nwabueze (kosinw [at] mit [dot] edu)
* Copyright:  2023
* Details:    Implements CPU emulator for HackMIT 2023 puzzle challenges.
*********************************************************************/

/*************************** HEADER FILES ***************************/

#include "crypto.h"
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/****************************** MACROS ******************************/

#define VM_RAM_SIZE    1024*1024*128
#define VM_RAM_BASE    0x80000000
#define VM_RAM_STOP    VM_RAM_BASE + VM_RAM_SIZE

//
//  VM opcodes
//
#define VM_OP_LUI               0x37
#define VM_OP_AUIPC             0x17

#define VM_OP_JAL               0x6F
#define VM_OP_JALR              0x67

#define VM_OP_BRANCH            0x63
#define VM_FUNCT3_BEQ           0x00
#define VM_FUNCT3_BNE           0x01
#define VM_FUNCT3_BLT           0x04
#define VM_FUNCT3_BGE           0x05
#define VM_FUNCT3_BLTU          0x06
#define VM_FUNCT3_BGEU          0x07

#define VM_OP_LOAD              0x03
#define VM_FUNCT3_LB            0x00
#define VM_FUNCT3_LH            0x01
#define VM_FUNCT3_LW            0x02
#define VM_FUNCT3_LBU           0x04
#define VM_FUNCT3_LHU           0x05

#define VM_OP_STORE             0x23
#define VM_FUNCT3_SB            0x00
#define VM_FUNCT3_SH            0x01
#define VM_FUNCT3_SW            0x02

#define VM_OP_ALU               0x33
#define VM_OP_ALUI              0x13

#define VM_FUNCT3_ADD           0x00
#define VM_FUNCT3_SHL           0x01
#define VM_FUNCT3_SLT           0x02
#define VM_FUNCT3_SLTU          0x03
#define VM_FUNCT3_XOR           0x04
#define VM_FUNCT3_SHR           0x05
#define VM_FUNCT3_OR            0x06
#define VM_FUNCT3_AND           0x07

#define VM_FUNCT3_MUL           0x00
#define VM_FUNCT3_MULH          0x01
#define VM_FUNCT3_MULHSU        0x02
#define VM_FUNCT3_MULHU         0x03
#define VM_FUNCT3_DIV           0x04
#define VM_FUNCT3_DIVU          0x05
#define VM_FUNCT3_REM           0x06
#define VM_FUNCT3_REMU          0x07

#define VM_FUNCT7_00            0x00
#define VM_FUNCT7_20            0x20
#define VM_FUNCT7_01            0x01

#define VM_OP_ECALL             0x73

#define ANSI_RED                "\x1b[31m"
#define ANSI_GREEN              "\x1b[32m"
#define ANSI_CLEAR              "\x1b[0m"

//
//  Helper macros for tracing
//
#define _VM_TRACE(fd, x, ...)                       \
    do {                                            \
        if (opt_trace)                              \
            fprintf(fd, x "\n", ##__VA_ARGS__);     \
    } while (0)

#define VM_TRACE_INFO(x, ...)   _VM_TRACE(stderr, "[" ANSI_GREEN "+" ANSI_CLEAR "] " x, ##__VA_ARGS__)
#define VM_TRACE_ERROR(x, ...)  _VM_TRACE(stderr, "[" ANSI_RED   "-" ANSI_CLEAR "] " x, ##__VA_ARGS__)

//
//  Helper macros for checking aligned and valid memory access
//
#define VM_CHECK_ALIGN_ACCESS(addr)                 \
    do {                                            \
        if ( (addr & 0x3) ) {                       \
            VM_TRACE_ERROR("misaligned memory access, address=0x%08x", addr); \
            return false;                           \
        }                                           \
    } while (0)

#define VM_CHECK_MEMORY_ACCESS(addr, sz)            \
    do {                                            \
        if (addr < VM_RAM_BASE) {                   \
            VM_TRACE_ERROR("memory out of bounds access, address=0x%08x", addr); \
            return false;                           \
        }                                           \
        if (addr + sz > VM_RAM_STOP) {              \
            VM_TRACE_ERROR("memory out of bounds access, address=0x%08x", addr); \
            return false;                           \
        }                                           \
    } while (0)                                     \


//
//  Helper macros for parsing RISC-V instructions
//
#define PARSE_IMM_I(v)          (((v) & 0xfff00000) >> 20)
#define PARSE_IMM_S(v)          ((((v) & 0xfe000000) >> 20 ) | (((v) >> 7) & 0x1F))
#define PARSE_IMM_B(v)          ((((v) & 0x80000000) >> 19) | (((v) & 0x80) << 4) | (((v) >> 20) & 0x7e0) | (((v) >> 7) & 0x1e))
#define PARSE_IMM_U(v)          (((v) & 0xfffff999) >> 12)
#define PARSE_IMM_J(v)          ((((v) & 0x80000000) >> 11) | ((v) & 0xff000) | (((v) >> 9) & 0x800) | (((v) >> 20) & 0x7fe))

//
//  Other helper macros
//
#define MIN(x,y)                ((x) < (y) ? (x) : (y))


//
//  from https://www.kneda.net/documentos/Programming%20Linux%20Anti-Reversing%20Techniques.pdf
//
#define XOR_STRING0(storage, string, key)
#define XOR_STRING1(storage, string, key)  storage[ 0] = string[ 0] ^ key; XOR_STRING0(storage, string, key);
#define XOR_STRING2(storage, string, key)  storage[ 1] = string[ 1] ^ key; XOR_STRING1(storage, string, key);
#define XOR_STRING3(storage, string, key)  storage[ 2] = string[ 2] ^ key; XOR_STRING2(storage, string, key);
#define XOR_STRING4(storage, string, key)  storage[ 3] = string[ 3] ^ key; XOR_STRING3(storage, string, key);
#define XOR_STRING5(storage, string, key)  storage[ 4] = string[ 4] ^ key; XOR_STRING4(storage, string, key);
#define XOR_STRING6(storage, string, key)  storage[ 5] = string[ 5] ^ key; XOR_STRING5(storage, string, key);
#define XOR_STRING7(storage, string, key)  storage[ 6] = string[ 6] ^ key; XOR_STRING6(storage, string, key);
#define XOR_STRING8(storage, string, key)  storage[ 7] = string[ 7] ^ key; XOR_STRING7(storage, string, key);
#define XOR_STRING9(storage, string, key)  storage[ 8] = string[ 8] ^ key; XOR_STRING8(storage, string, key);
#define XOR_STRING10(storage, string, key) storage[ 9] = string[ 9] ^ key; XOR_STRING9(storage, string, key);
#define XOR_STRING11(storage, string, key) storage[10] = string[10] ^ key; XOR_STRING10(storage, string, key);
#define XOR_STRING12(storage, string, key) storage[11] = string[11] ^ key; XOR_STRING11(storage, string, key);
#define XOR_STRING13(storage, string, key) storage[12] = string[12] ^ key; XOR_STRING12(storage, string, key);
#define XOR_STRING14(storage, string, key) storage[13] = string[13] ^ key; XOR_STRING13(storage, string, key);
#define XOR_STRING15(storage, string, key) storage[14] = string[14] ^ key; XOR_STRING14(storage, string, key);
#define XOR_STRING16(storage, string, key) storage[15] = string[15] ^ key; XOR_STRING15(storage, string, key);
#define XOR_STRING17(storage, string, key) storage[16] = string[16] ^ key; XOR_STRING16(storage, string, key);
#define XOR_STRING18(storage, string, key) storage[17] = string[17] ^ key; XOR_STRING17(storage, string, key);
#define XOR_STRING19(storage, string, key) storage[18] = string[18] ^ key; XOR_STRING18(storage, string, key);
#define XOR_STRING20(storage, string, key) storage[19] = string[19] ^ key; XOR_STRING19(storage, string, key);
#define XOR_STRING21(storage, string, key) storage[20] = string[20] ^ key; XOR_STRING20(storage, string, key);
#define XOR_STRING22(storage, string, key) storage[21] = string[21] ^ key; XOR_STRING21(storage, string, key);
#define XOR_STRING23(storage, string, key) storage[22] = string[22] ^ key; XOR_STRING22(storage, string, key);
#define XOR_STRING24(storage, string, key) storage[23] = string[23] ^ key; XOR_STRING23(storage, string, key);
#define XOR_STRING25(storage, string, key) storage[24] = string[24] ^ key; XOR_STRING24(storage, string, key);
#define XOR_STRING26(storage, string, key) storage[25] = string[25] ^ key; XOR_STRING25(storage, string, key);
#define XOR_STRING27(storage, string, key) storage[26] = string[26] ^ key; XOR_STRING26(storage, string, key);
#define XOR_STRING28(storage, string, key) storage[27] = string[27] ^ key; XOR_STRING27(storage, string, key);
#define XOR_STRING29(storage, string, key) storage[28] = string[28] ^ key; XOR_STRING28(storage, string, key);
#define XOR_STRING30(storage, string, key) storage[29] = string[29] ^ key; XOR_STRING29(storage, string, key);
#define XOR_STRING31(storage, string, key) storage[30] = string[30] ^ key; XOR_STRING30(storage, string, key);
#define XOR_STRING32(storage, string, key) storage[31] = string[31] ^ key; XOR_STRING31(storage, string, key);

#define DEFINE_XOR_STRING(storage, string, length, key) \
    char storage[length+1] = {};                        \
    do {                                                \
        XOR_STRING##length(storage, string, key);       \
        x(storage, length, key);                        \
    } while (0)

//
//  Macros for vm execution DSL
//
#define OPCODE                  inst->opcode
#define FUNCT3                  inst->funct3
#define FUNCT7                  inst->funct7
#define OTHERWISE               default:
#define MATCH(x)                switch (x)
#define MATCHES(x)              case (x):
#define END                     break
#define RD                      ctx->registers[inst->rd]
#define RS1                     ctx->registers[inst->rs1]
#define RS2                     ctx->registers[inst->rs2]
#define IMM12i                  inst->imm12i
#define IMM12s                  inst->imm12s
#define IMM12b                  inst->imm12b
#define IMM20u                  inst->imm20u
#define IMM20j                  inst->imm20j
#define SHAMT                   inst->shamt
#define PC                      ctx->pc
#define ENDPC                   PC = PC + 4; END
#define SX                      true
#define ZX                      false
#define BYTE                    8
#define HALFWORD                16
#define WORD                    32
#define LOAD(a, sz, flag)       vm_load_ex(ctx, a, sz, flag)
#define STORE(a, sz, v)         vm_store_ex(ctx, a, sz, v)
#define IS_SHIFT                ( ( inst->funct3 == VM_FUNCT3_SHL ) || ( inst->funct3 == VM_FUNCT3_SHR ) )
#define R0                      ctx->registers[0]
#define A0                      ctx->registers[10]
#define A1                      ctx->registers[11]
#define A2                      ctx->registers[12]
#define A7                      ctx->registers[17]

/**************************** DATA TYPES ****************************/

struct vm_context {
    uint32_t    pc;
    uint32_t    registers[32];
    uint8_t     memory[VM_RAM_SIZE];
} ctx;

struct vm_instruction {
    uint8_t opcode;
    uint8_t rd;
    uint8_t rs1;
    uint8_t rs2;
    uint8_t funct3;
    uint8_t funct7;
    int32_t imm12i;
    int32_t imm12s;
    int32_t imm12b;
    int32_t imm20u;
    int32_t imm20j;
    uint8_t shamt;
};

/*********************** FUNCTION DECLARATIONS **********************/

bool vm_context_init(struct vm_context *ctx);
bool vm_context_step(struct vm_context *ctx);
bool vm_read_byte(struct vm_context *ctx, uint32_t addr, uint32_t *out);
bool vm_read_halfword(struct vm_context *ctx, uint32_t addr, uint32_t *out);
bool vm_read_word(struct vm_context *ctx, uint32_t addr, uint32_t *out);
bool vm_store_byte(struct vm_context *ctx, uint32_t addr, uint32_t val);
bool vm_store_halfword(struct vm_context *ctx, uint32_t addr, uint32_t val);
bool vm_store_word(struct vm_context *ctx, uint32_t addr, uint32_t val);

/*********************** VARIABLES **********************/

const char *opt_filename = NULL;
bool opt_trace = false;

/*********************** FUNCTION DEFINITIONS **********************/

void x(char* string, int length, char key)
{
    for (int i = 0; i < length; i++) {
        string[i] = string[i] ^ key;
    }
}

bool parse_args(int argc, char **argv)
{
    DEFINE_XOR_STRING(s_help, "--help", 6, 0xe4);
    DEFINE_XOR_STRING(s_trace, "--trace", 7, 0x93);
    DEFINE_XOR_STRING(s_unknown_arg, "unknown argument \"%s\"\n", 22, 0xe4);

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];

        if (arg[0] == '-') {
            if (strcmp(arg, s_help) == 0)
                return false;

            else if (strcmp(arg, s_trace) == 0) { // secret option to help solve chall
                opt_trace = true;
                continue;
            }

            fprintf(stderr, s_unknown_arg, arg);
            return false;
        }

        opt_filename = arg;
    }

    return opt_filename != NULL;
}

bool vm_context_init(struct vm_context *ctx)
{
    void *elf_base = NULL;
    off_t file_size = 0;
    int fd = -1;

    if( opt_filename == NULL) {
        return false;
    }

    ctx->registers[0] = 0;
    ctx->registers[2] = VM_RAM_STOP;
    ctx->pc           = VM_RAM_BASE;

    fd = open(opt_filename, O_RDONLY);

    if (fd == -1) {
       goto exit;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        goto exit;
    }
    file_size = MIN(st.st_size, VM_RAM_STOP);

    elf_base = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (elf_base == MAP_FAILED) {
        goto exit;
    }

    Elf32_Ehdr *hdr = (Elf32_Ehdr *)elf_base;

    if (hdr->e_ident[EI_MAG0] != ELFMAG0 ||
        hdr->e_ident[EI_MAG1] != ELFMAG1 ||
        hdr->e_ident[EI_MAG2] != ELFMAG2 ||
        hdr->e_ident[EI_MAG3] != ELFMAG3) { goto exit; }

    if (hdr->e_machine != EM_NONE) { goto exit; }
    if (hdr->e_type != ET_EXEC) { goto exit; }

    Elf32_Phdr *phdr = (Elf32_Phdr *)((uintptr_t)elf_base + hdr->e_phoff);

    for (int i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        off_t segment_offset = phdr[i].p_offset;
        void *segment_address = &ctx->memory[phdr[i].p_vaddr - VM_RAM_BASE];
        void *file_offset = (void *)((uintptr_t)elf_base + segment_offset);

        if (segment_offset + phdr[i].p_filesz > file_size) {
            goto exit;
        }

        memcpy(segment_address, file_offset, phdr[i].p_filesz);
    }

    munmap(elf_base, file_size);
    close(fd);
    return true;

exit:
    if (elf_base != NULL) { munmap(elf_base, file_size); }
    if (fd != -1) { close(fd); }
    return false;
}

//
//  from http://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend
//
int32_t sign_extend32(int32_t x, unsigned b)
{
    int32_t r;
    int const m = 1U << (b - 1);
    x = x & ((1U << b) - 1);
    r = (x ^ m) - m;
    return r;
}

struct vm_instruction parse_vm_inst(uint32_t word)
{
    struct vm_instruction result = {0};
    result.opcode   = (uint8_t) ( word & 0x7F );
    result.rd       = (uint8_t) ( ( word >> 7 ) & 0x1F );
    result.rs1      = (uint8_t) ( ( word >> 15 ) & 0x1F );
    result.rs2      = (uint8_t) ( ( word >> 20 ) & 0x1F );
    result.funct3   = (uint8_t) ( ( word >> 12 ) & 0x07 );
    result.funct7   = (uint8_t) ( ( word >> 25 ) & 0x7F );
    result.imm12i   = sign_extend32(PARSE_IMM_I(word), 12);
    result.imm12s   = sign_extend32(PARSE_IMM_S(word), 12);
    result.imm12b   = sign_extend32(PARSE_IMM_B(word), 12);
    result.imm20u   = sign_extend32(PARSE_IMM_U(word), 20);
    result.imm20j   = sign_extend32(PARSE_IMM_J(word), 20);
    result.shamt    = (uint8_t) ( PARSE_IMM_I(word) & 0x1f );
    return result;
}

uint32_t vm_load_ex(struct vm_context *ctx, uint32_t addr, uint32_t sz, bool sx)
{
    uint32_t result = 0;

    switch (sz)
    {
        case 8:     vm_read_byte(ctx, addr, &result); break;
        case 16:    vm_read_halfword(ctx, addr, &result); break;
        case 32:    vm_read_word(ctx, addr, &result); break;
    }

    if (sx)
        result = (uint32_t)sign_extend32((int32_t)result, sz);

    return result;
}

void vm_store_ex(struct vm_context *ctx, uint32_t addr, uint32_t sz, uint32_t v)
{
    switch (sz)
    {
        case 8:     vm_store_byte(ctx, addr, v); break;
        case 16:    vm_store_halfword(ctx, addr, v); break;
        case 32:    vm_store_word(ctx, addr, v); break;
    }
}

uint32_t xxprint(const char *ciphertext, unsigned int length, const char *key)
{
    uint8_t hash[SHA256_BLOCK_SIZE];
    uint8_t iv[AES256_BLOCKLEN];
    uint8_t *plaintext;
    uint32_t plaintext_len;
    struct sha256_state sha_st;
    struct aes256_state aes_st;

    plaintext_len = length - sizeof(iv);
    plaintext = (uint8_t *)calloc(1, plaintext_len + 1);

    sha256_init(&sha_st);
    sha256_update(&sha_st, (uint8_t *)key, strlen(key));
    sha256(&sha_st, hash);

    memcpy(iv, ciphertext, sizeof(iv));
    memcpy(plaintext, (void*)((uintptr_t)ciphertext + sizeof(iv)), plaintext_len);

    aes256_init(&aes_st, hash, iv);
    aes256_decrypt(&aes_st, plaintext, plaintext_len);

    printf("%s", plaintext);

    free(plaintext);

    return 0;
}

uint32_t vm_handle_ecall(struct vm_context *ctx, uint32_t syscall, uint32_t a0, uint32_t a1, uint32_t a2)
{
    VM_TRACE_INFO("syscall=0x%08x, a0=0x%08x, a1=0x%08x, a2=0x%08x", syscall, a0, a1, a2);

    switch (syscall)
    {
        case 63:        { return (uint32_t)read((int)a0, &ctx->memory[a1 - VM_RAM_BASE], (size_t)a2); }
        case 64:        { return (uint32_t)write((int)a0, &ctx->memory[a1 - VM_RAM_BASE], (size_t)a2); }
        case 93:        { exit((int)a0); }
        case 27:        { return xxprint((const char *)&ctx->memory[a0 - VM_RAM_BASE], (unsigned int)a1, (const char *)&ctx->memory[a2 - VM_RAM_BASE]); }
        default:        { VM_TRACE_ERROR("unknown syscall number"); exit(1); }
    }

    return a0;
}

bool vm_context_execute(struct vm_context *ctx, struct vm_instruction *inst)
{
    R0 = 0; VM_CHECK_ALIGN_ACCESS(PC);

    MATCH (OPCODE)
    {
        MATCHES (VM_OP_LUI)                 { RD = (uint32_t)IMM20u << 12; ENDPC; }
        MATCHES (VM_OP_AUIPC)               { RD = PC + ( (uint32_t)IMM20u << 12 ); ENDPC; }
        MATCHES (VM_OP_JAL)                 { RD = PC + 4; PC = PC + IMM20j; END; }
        MATCHES (VM_OP_JALR)                { uint32_t TMP = RS1; RD = PC + 4; PC = (TMP + IMM12i) & ~0x01; END; }
        MATCHES (VM_OP_BRANCH)
        {
            MATCH (FUNCT3)
            {
                MATCHES (VM_FUNCT3_BEQ)     { PC = ( RS1 == RS2 ) ? ( PC + IMM12b ) : ( PC + 4 ); END; }
                MATCHES (VM_FUNCT3_BNE)     { PC = ( RS1 != RS2 ) ? ( PC + IMM12b ) : ( PC + 4 ); END; }
                MATCHES (VM_FUNCT3_BLT)     { PC = ( (int32_t)RS1 < (int32_t)RS2 ) ? ( PC + IMM12b ) : ( PC + 4 ); END; }
                MATCHES (VM_FUNCT3_BGE)     { PC = ( (int32_t)RS1 >= (int32_t)RS2 ) ? ( PC + IMM12b ) : ( PC + 4 ); END; }
                MATCHES (VM_FUNCT3_BLTU)    { PC = ( RS1 < RS2 ) ? ( PC + IMM12b ) : ( PC + 4 ); END; }
                MATCHES (VM_FUNCT3_BGEU)    { PC = ( RS1 >= RS2 ) ? ( PC + IMM12b ) : ( PC + 4 ); END; }
                OTHERWISE                   { return false; }
            }
            END;
        }
        MATCHES (VM_OP_LOAD)
        {
            MATCH (FUNCT3)
            {
                MATCHES (VM_FUNCT3_LB)      { RD = LOAD(RS1 + IMM12i, BYTE, SX); ENDPC; }
                MATCHES (VM_FUNCT3_LH)      { RD = LOAD(RS1 + IMM12i, HALFWORD, SX); ENDPC; }
                MATCHES (VM_FUNCT3_LW)      { RD = LOAD(RS1 + IMM12i, WORD, ZX); ENDPC; }
                MATCHES (VM_FUNCT3_LBU)     { RD = LOAD(RS1 + IMM12i, BYTE, ZX); ENDPC; }
                MATCHES (VM_FUNCT3_LHU)     { RD = LOAD(RS1 + IMM12i, HALFWORD, ZX); ENDPC; }
                OTHERWISE                   { return false; }
            }
            END;
        }
        MATCHES (VM_OP_STORE)
        {
            MATCH (FUNCT3)
            {
                MATCHES (VM_FUNCT3_SB)      { STORE(RS1 + IMM12s, BYTE, RS2); ENDPC; }
                MATCHES (VM_FUNCT3_SH)      { STORE(RS1 + IMM12s, HALFWORD, RS2); ENDPC; }
                MATCHES (VM_FUNCT3_SW)      { STORE(RS1 + IMM12s, WORD, RS2); ENDPC; }
                OTHERWISE                   { return false; }
            }
            END;
        }
        MATCHES (VM_OP_ALU)
        {
            if (FUNCT7 == VM_FUNCT7_01)
            {
                MATCH (FUNCT3)
                {
                    MATCHES (VM_FUNCT3_MUL)         { RD = ( RS1 * RS2 ) & 0xFFFFFFFF; ENDPC; }
                    MATCHES (VM_FUNCT3_MULH)        { RD = (uint32_t) ( ( (int64_t)RS1 * (int64_t)RS2 ) >> 32 ); ENDPC; }
                    MATCHES (VM_FUNCT3_MULHU)       { RD = (uint32_t) ( ( ( (uint64_t)RS1 *  (uint64_t)RS2 ) ) >> 32 ); ENDPC; }
                    MATCHES (VM_FUNCT3_MULHSU)      { RD = (uint32_t) ( ( (int64_t)RS1 * RS2 ) >> 32 ); ENDPC; }
                    MATCHES (VM_FUNCT3_DIV)         { RD = (uint32_t) ( (int32_t)RS1 / (int32_t)RS2 ); ENDPC; }
                    MATCHES (VM_FUNCT3_DIVU)        { RD = RS1 / RS2; ENDPC; }
                    MATCHES (VM_FUNCT3_REM)         { RD = (uint32_t) ( (int32_t)RS1 % (int32_t)RS2 ); ENDPC; }
                    MATCHES (VM_FUNCT3_REMU)        { RD = RS1 % RS2; ENDPC; }
                    OTHERWISE                       { return false; }
                }

                return true;
            }

            MATCH (FUNCT3)
            {
                MATCHES (VM_FUNCT3_ADD)
                {
                    MATCH (FUNCT7)
                    {
                        MATCHES (VM_FUNCT7_00)      { RD = (uint32_t)((int32_t)RS1 + (int32_t)RS2); ENDPC; }
                        MATCHES (VM_FUNCT7_20)      { RD = (uint32_t)((int32_t)RS1 - (int32_t)RS2); ENDPC; }
                        OTHERWISE                   { return false; }
                    }
                    END;
                }
                MATCHES (VM_FUNCT3_SHL)             { RD = RS1 << ( RS2 & 0x1F ); ENDPC; }
                MATCHES (VM_FUNCT3_SLT)             { RD = ( (int32_t)RS1 < (int32_t)RS2 ) ? 1 : 0; ENDPC; }
                MATCHES (VM_FUNCT3_SLTU)            { RD = ( RS1 < RS2 ) ? 1 : 0; ENDPC; }
                MATCHES (VM_FUNCT3_XOR)             { RD = RS1 ^ RS2; ENDPC; }
                MATCHES (VM_FUNCT3_SHR)
                {
                    MATCH (FUNCT7)
                    {
                        MATCHES (VM_FUNCT7_00)      { RD = RS1 >> ( RS2 & 0x1F ); ENDPC; }
                        MATCHES (VM_FUNCT7_20)      { RD = (uint32_t)( (int32_t)RS1 >> ( RS2 & 0x1F ) ); ENDPC; }
                        OTHERWISE                   { return false; }
                    }
                    END;
                }
                MATCHES (VM_FUNCT3_OR)              { RD = RS1 | RS2; ENDPC; }
                MATCHES (VM_FUNCT3_AND)             { RD = RS1 & RS2; ENDPC; }
                OTHERWISE                           { return false; }
            }
            END;
        }
        MATCHES (VM_OP_ALUI)
        {
            uint32_t OTHER = IS_SHIFT ? (uint32_t)SHAMT : (uint32_t)IMM12i;

            MATCH (FUNCT3)
            {
                MATCHES (VM_FUNCT3_ADD)             { RD = (uint32_t)((int32_t)RS1 + (int32_t)OTHER); ENDPC; }
                MATCHES (VM_FUNCT3_SHL)             { RD = RS1 << ( OTHER & 0x1F ); ENDPC; }
                MATCHES (VM_FUNCT3_SLT)             { RD = ( (int32_t)RS1 < (int32_t)OTHER ) ? 1 : 0; ENDPC; }
                MATCHES (VM_FUNCT3_SLTU)            { RD = ( RS1 < OTHER ) ? 1 : 0; ENDPC; }
                MATCHES (VM_FUNCT3_XOR)             { RD = RS1 ^ OTHER; ENDPC; }
                MATCHES (VM_FUNCT3_SHR)
                {
                    MATCH (FUNCT7)
                    {
                        MATCHES (VM_FUNCT7_00)      { RD = RS1 >> ( OTHER & 0x1F ); ENDPC; }
                        MATCHES (VM_FUNCT7_20)      { RD = (uint32_t)( (int32_t)RS1 >> ( OTHER & 0x1F ) ); ENDPC; }
                        OTHERWISE                   { return false; }
                    }
                    END;
                }
                MATCHES (VM_FUNCT3_OR)              { RD = RS1 | OTHER; ENDPC; }
                MATCHES (VM_FUNCT3_AND)             { RD = RS1 & OTHER; ENDPC; }
                OTHERWISE                           { return false; }
            }
            END;
        }
        MATCHES (VM_OP_ECALL)               { A0 = vm_handle_ecall(ctx, A7, A0, A1, A2); ENDPC; }
        OTHERWISE                           { return false; }
    }

    return true;
}

bool vm_context_step(struct vm_context *ctx)
{
    uint32_t w = 0;

    if (!vm_read_word(ctx, ctx->pc, &w)) {
        return false;
    }

    struct vm_instruction inst = parse_vm_inst(w);

    VM_TRACE_INFO("address=0x%08x, instruction=0x%08x", ctx->pc, w);

    if (!vm_context_execute(ctx, &inst)) {
        VM_TRACE_ERROR("halting @ address=0x%08x, instruction=0x%08x", ctx->pc, w);
        return false;
    }

    return true;
}

bool vm_read_byte(struct vm_context *ctx, uint32_t addr, uint32_t *out)
{
    VM_CHECK_MEMORY_ACCESS(addr, 1);
    *out = (uint32_t) ctx->memory[addr - VM_RAM_BASE];
    return true;
}

bool vm_read_halfword(struct vm_context *ctx, uint32_t addr, uint32_t *out)
{
    VM_CHECK_MEMORY_ACCESS(addr, 2);
    *out = (uint32_t) ctx->memory[addr - VM_RAM_BASE]
         | (uint32_t) ctx->memory[addr - VM_RAM_BASE + 1] << 8;
    return true;
}

bool vm_read_word(struct vm_context *ctx, uint32_t addr, uint32_t *out)
{
    VM_CHECK_MEMORY_ACCESS(addr, 4);
    *out = (uint32_t) ctx->memory[addr - VM_RAM_BASE]
         | (uint32_t) ctx->memory[addr - VM_RAM_BASE + 1] << 8
         | (uint32_t) ctx->memory[addr - VM_RAM_BASE + 2] << 16
         | (uint32_t) ctx->memory[addr - VM_RAM_BASE + 3] << 24;
    return true;
}

bool vm_store_byte(struct vm_context *ctx, uint32_t addr, uint32_t val)
{
    VM_CHECK_MEMORY_ACCESS(addr, 1);
    ctx->memory[addr - VM_RAM_BASE]     = (uint8_t) ( val & 0xFF );
    return true;
}

bool vm_store_halfword(struct vm_context *ctx, uint32_t addr, uint32_t val)
{
    VM_CHECK_MEMORY_ACCESS(addr, 2);
    ctx->memory[addr - VM_RAM_BASE]     = (uint8_t) ( val & 0xFF );
    ctx->memory[addr - VM_RAM_BASE + 1] = (uint8_t) ( (val >> 8) & 0xFF );
    return true;
}

bool vm_store_word(struct vm_context *ctx, uint32_t addr, uint32_t val)
{
    VM_CHECK_MEMORY_ACCESS(addr, 4);
    ctx->memory[addr - VM_RAM_BASE]     = (uint8_t) ( val & 0xFF );
    ctx->memory[addr - VM_RAM_BASE + 1] = (uint8_t) ( (val >> 8) & 0xFF );
    ctx->memory[addr - VM_RAM_BASE + 2] = (uint8_t) ( (val >> 16) & 0xFF );
    ctx->memory[addr - VM_RAM_BASE + 3] = (uint8_t) ( (val >> 24) & 0xFF );
    return true;
}

int main(int argc, char** argv)
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    if (!parse_args(argc, argv)) {
        fprintf(stderr, "usage: %s [options] <filename>\n", argv[0]);
        return 1;
    }

    if (!vm_context_init(&ctx)) {
        fprintf(stderr, "could not load program '%s'\n", opt_filename);
        return 1;
    }

    while (vm_context_step(&ctx)) { }

    return 1;
}