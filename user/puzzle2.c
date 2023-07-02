#include "user/user.h"
#include "user/puzzle2.h"

#define ANSI_BOLD       "\x1b[1m"
#define ANSI_CLEAR      "\x1b[0m"
#define ANSI_GREEN      "\x1b[32m"
#define ANSI_RED        "\x1b[31m"

const char ciphertext[] = {0x2d, 0x46, 0xed, 0xe3, 0xdf, 0x39, 0x9e, 0x9c, 0xd4, 0x4e, 0x16, 0x5d, 0x42, 0xc8, 0xb, 0xe8, 0x37, 0x18, 0x7c, 0x80, 0xa6, 0x9, 0xec, 0xe, 0xb5, 0x83, 0xe2, 0xd3, 0x69, 0xdf, 0xe8, 0xa7, 0xec, 0xe, 0xc5, 0xcf, 0xda, 0x94, 0x97, 0x3c, 0x6c, 0x4a, 0xc0, 0x1e, 0xa3, 0x94, 0x97, 0x1e, 0x2e, 0xf6, 0xf2, 0xb7, 0xd6, 0xc1, 0x73, 0xf7, 0x6b, 0xa8, 0xfb, 0xbf, 0x3d, 0x6e, 0x54, 0xa6, 0xff, 0xfa, 0x43, 0xa4, 0x0, 0x9a, 0x71, 0x36, 0x96, 0xb7, 0xdd, 0xb0, 0xed, 0xb1, 0xc0};

#define KEY_LEN 64

void win(char *password)
{
    puts("[" ANSI_GREEN "*" ANSI_CLEAR "] " "drats, i guess i owe you a flag now!");
    printf("[" ANSI_GREEN "*" ANSI_CLEAR "] " "here is the flag: ");
    xxprint(ciphertext, sizeof(ciphertext), password);
    puts("");
    puts("[" ANSI_GREEN "*" ANSI_CLEAR "] " "also have a beaver for your troubles: ");

    puts("\n"
"                   |    :|\n"
"                   |     |\n"
"                   |    .|\n"
"               ____|    .|\n"
"             .' .  ).   ,'\n"
"           .' c   '7 ) (\n"
"       _.-\"       |.'   `.\n"
"     .'           \"8E   :|\n"
"     |          _}\"\"    :|\n"
"     |         (   |     |\n"
"    .'         )   |    :|\n"
".odCG8o_.---.__8E  |    .|    \n"
"`Y8MMP\"\"       \"\"  `-...-'   cgmm\n");

}

int main(void)
{
    puts("\n"
" ██╗   ██╗███╗   ███╗██╗  ██╗ █████╗  ██████╗██╗  ██╗\n"
" ██║   ██║████╗ ████║██║  ██║██╔══██╗██╔════╝██║ ██╔╝\n"
" ██║   ██║██╔████╔██║███████║███████║██║     █████╔╝ \n"
" ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██╔══██║██║     ██╔═██╗ \n"
"  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║██║  ██║╚██████╗██║  ██╗\n"
"   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");


    puts("~ the state-of-the-art passphrase checker powered by AI and beavers (i think?) ~");
    puts("  we use machine learning models or something to update the program as it executes ");
    puts("");
    puts("[" ANSI_GREEN "*" ANSI_CLEAR "] remember to submit the " ANSI_BOLD "flag" ANSI_CLEAR ", not the passphrase on the command center!" ANSI_CLEAR);
    printf("[" ANSI_GREEN "*" ANSI_CLEAR "] " "enter passphrase: ");

    char buf[128];
    gets(buf, 128);
    buf[strlen(buf) - 1] = '\0';

    if (strlen(buf) != KEY_LEN)
    {
        exit(1);
    }

    ((void(*)(char*, uint32_t))code)(buf, (uint32_t)(code + 0x44));

    win(buf);

    return 0;
}