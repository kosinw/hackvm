#define SYS_read            63
#define SYS_write           64
#define SYS_exit            93
#define SYS_print_flag      0x1337

.global read
read:
    li a7, SYS_read
    ecall
    ret

.global write
write:
    li a7, SYS_write
    ecall
    ret

.global exit
exit:
    li a7, SYS_exit
    ecall
    ret

.global print_flag
print_flag:
    li a7, SYS_print_flag
    ecall
    ret