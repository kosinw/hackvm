#include "user/user.h"

#define BUF_SIZE    128
#define KEY_LEN     47

#define ANSI_BOLD       "\x1b[1m"
#define ANSI_CLEAR      "\x1b[0m"
#define ANSI_GREEN      "\x1b[32m"
#define ANSI_RED        "\x1b[31m"

struct xorshift128p_state
{
    uint64_t x[2];
};

const char password[] = {0xcf, 0xd4, 0xe0, 0xeb, 0xd8, 0x40, 0x7c, 0x32, 0x2d, 0x30, 0xef, 0x6b, 0x20, 0x4c, 0xdb, 0x59, 0x63, 0xd1, 0x46, 0x97, 0x66, 0x42, 0x14, 0x5, 0xca, 0x45, 0xba, 0xa0, 0x4, 0xf, 0x40, 0xc4, 0xa, 0xb0, 0x4a, 0x64, 0x21, 0x1e, 0x8d, 0x8a, 0x8f, 0xdc, 0xaf, 0x78, 0x1d, 0xd1, 0x27, 0x87, 0xa0, 0xe8, 0x77, 0x87, 0x3a, 0x2d, 0x66, 0x75, 0x98, 0x30, 0xed, 0xc7, 0x30, 0x27, 0xa0, 0x6b, 0x3a, 0x34, 0x48, 0x4a, 0x93, 0x99, 0x68, 0x7d, 0x64, 0x36, 0xd0, 0xf0, 0xb2, 0xe4, 0xee, 0x7b, 0x9d, 0x61, 0xaa, 0x21, 0x9a, 0xca, 0xf9, 0x3f, 0xe7, 0xe9, 0x43, 0x55, 0x59, 0xfd, 0x70, 0x86, 0xe8, 0x54, 0x52, 0xfd, 0x16, 0x1a, 0x97, 0xde, 0x16, 0xc8, 0x92, 0x74, 0x9b, 0x1f, 0x2c, 0x1b, 0x47, 0xaf, 0x8c, 0xf1, 0xf2, 0x44, 0xa4, 0x2d, 0xd, 0x4c, 0x6b, 0xf6, 0x33, 0x1a, 0xc, 0xff, 0x71, 0x3b, 0xd9, 0xbd, 0xc4, 0x4a, 0xa8, 0x9f, 0x17, 0x88, 0x97, 0xd7, 0x6c, 0xaa, 0x90, 0x9f, 0x28, 0x6d, 0xb1, 0x8d, 0xce, 0xe2, 0xcc, 0x29, 0xa5, 0xba, 0x6, 0xf3, 0x7a, 0x5b, 0x79, 0xae, 0x6, 0x89, 0xc, 0x8f, 0x3f, 0x52, 0x72, 0xa6, 0xb3, 0x31, 0x29, 0x98, 0xa7, 0x5a, 0x71, 0xbf, 0xca, 0x2e, 0xf, 0x57, 0x11, 0x8, 0x2d, 0xbb, 0x34, 0x83, 0x1, 0xdc};
const char ciphertext[] = {0xf6, 0x31, 0x93, 0x3f, 0x36, 0x30, 0x93, 0x4b, 0xf9, 0x99, 0xb3, 0xca, 0x0, 0x87, 0xab, 0xb3, 0x40, 0x87, 0x2, 0xd1, 0x62, 0xc8, 0x8c, 0x18, 0xf7, 0x71, 0x57, 0x1e, 0x72, 0x78, 0x1b, 0xe2, 0xc9, 0xd9, 0x42, 0xd3, 0x7f, 0x4f, 0xdb, 0xc3, 0xf8, 0x5, 0x65, 0x2f, 0x5, 0xf6, 0x42, 0x44, 0xc1, 0xb1, 0xb2, 0x74, 0x8e, 0x42, 0x42, 0xe3, 0x79, 0xb8, 0x3f, 0x71, 0x71, 0x47, 0xec};

uint32_t murmur3_scramble(uint32_t k) 
{
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}

uint32_t murmur3(const uint8_t* key, size_t len, uint32_t seed)
{
	uint32_t h = seed;
    uint32_t k;
    for (uint32_t i = len >> 2; i; i--) {
        memcpy(&k, key, sizeof(uint32_t));
        key += sizeof(uint32_t);
        h ^= murmur3_scramble(k);
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    k = 0;
    for (uint32_t i = len & 3; i; i--) {
        k <<= 8;
        k |= key[i - 1];
    }
    h ^= murmur3_scramble(k);
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

uint64_t xorshift128p(struct xorshift128p_state *state)
{
	uint64_t t = state->x[0];
	uint64_t const s = state->x[1];
	state->x[0] = s;
	t ^= t << 23;
	t ^= t >> 18;
	t ^= s ^ (s >> 5);
	state->x[1] = t;
	return t + s;
}

void wrong_password(void)
{
    puts("[" ANSI_RED "!" ANSI_CLEAR "] " "sorry, login failed!");
    exit(1);
}

int memcmp(char *plaintext, const char *ciphertext, size_t n)
{
    struct xorshift128p_state s = { .x = { 0xa9662f37ce8d7c2, 0x2dc85cbda48610b } };
    uint8_t *x = (uint8_t *)plaintext;
    uint32_t *y = (uint32_t *)ciphertext;

    while (n-- > 0)
    {
        uint32_t a = murmur3(x, 1, (uint32_t)xorshift128p(&s));
        uint32_t b = murmur3((uint8_t*)&a, 4, (uint32_t)xorshift128p(&s));
        uint32_t c = a ^ b ^ (uint32_t)xorshift128p(&s);
        uint32_t d = (uint32_t)(((uint64_t)c * 0xe984385) >> 11);
        uint32_t e = (d << 14) | (d >> 18);
        if (e != *y) { return e - *y; }
        x++;
        y++;
    }

    return 0;
}

void win(char *password)
{
    puts("[" ANSI_GREEN "*" ANSI_CLEAR "] " "Welcome to bish, the beaver interactive shell");
    puts("[" ANSI_RED "$" ANSI_CLEAR "] " "cat flag.txt");
    print_flag(ciphertext, sizeof(ciphertext), password);
    puts("");
    puts("[" ANSI_GREEN "*" ANSI_CLEAR "] " "now shutting down shell...");
}

void password_check(void)
{
    char buf[128];
    gets(buf, BUF_SIZE);
    buf[strlen(buf) - 1] = '\0';
    
    if (strlen(buf) != KEY_LEN || memcmp(buf, password, KEY_LEN) != 0)
        wrong_password();

    win(buf);
}

int main(void)
{
    puts("");
    puts("          .=\"   \"=._.---.");
    puts("        .\"         c ' Y'`p               welcome to tim the beaver's");
    puts("       /   ,       `.  w_/             reduced instruction set computer");
    puts("       |   '-.   /     / ");
    puts(" _,..._|      )_-\\ \\_=.");
    puts("`-....-'`------)))`=-'\"`'\"");
    puts("");
    puts("[" ANSI_GREEN "*" ANSI_CLEAR "] "  "logging in as user timthebeaver");
    printf("[" ANSI_GREEN "*" ANSI_CLEAR "] " ANSI_BOLD  "enter passphrase: " ANSI_CLEAR);

    password_check();
    return 1;
}