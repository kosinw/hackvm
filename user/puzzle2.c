#include "user/user.h"
#include "user/puzzle2.h"

#define ANSI_BOLD       "\x1b[1m"
#define ANSI_CLEAR      "\x1b[0m"
#define ANSI_GREEN      "\x1b[32m"
#define ANSI_RED        "\x1b[31m"

const char ciphertext[] = {0x38, 0x4c, 0x24, 0x3, 0xe9, 0x4, 0x59, 0x14, 0xa4, 0x1b, 0xc9, 0xa4, 0xe2, 0x1, 0xc, 0x38, 0x20, 0xd8, 0xf9, 0x71, 0x58, 0x3a, 0x98, 0x30, 0xa4, 0x55, 0xf2, 0x81, 0x68, 0xa6, 0x3c, 0xe8, 0xb0, 0x14, 0x5e, 0x51, 0x1f, 0x3f, 0x14, 0x5c, 0x55, 0xf6, 0x59, 0xd1, 0xf0, 0x7, 0x90, 0x6f, 0x16, 0x5a, 0xe6, 0x81, 0xbb, 0xee, 0x99, 0x75, 0xb0, 0x4, 0xa5, 0x2a, 0x51, 0xfa, 0xdf, 0x74, 0x79, 0xcb, 0x1, 0x33, 0xd, 0xac, 0xb0, 0x2, 0x85, 0xe1, 0xd2, 0xe2, 0xdd, 0x52, 0xda, 0x4b};

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