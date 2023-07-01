#define SYS_read            63
#define SYS_write           64
#define SYS_exit            93
#define SYS_xxprint         27

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

.global xxprint
xxprint:
    li a7, SYS_xxprint
    ecall
    ret