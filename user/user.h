typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;
typedef unsigned int   size_t;

typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;

// system calls
int exit(int) __attribute__((noreturn));
int write(int, const void*, int);
int read(int, void*, int);
int print_flag(const char*, size_t, const char*);

// ulib.c
void fprintf(int, const char*, ...);
void printf(const char*, ...);
void puts(const char *);
char* gets(char*, int max);
uint strlen(const char*);
void* memset(void*, int, uint);
void* malloc(uint);
void *memcpy(void *, const void *, uint);
