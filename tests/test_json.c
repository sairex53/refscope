#define main refscope_cli_main
#include "../src/cli/main.c"
#undef main

int main(void)
{
    static const char utf8[] = "Привет";
    static const char escaped[] = "quote\" slash\\ tab\t";
    static const char invalid[] = {'A', (char)0xff, 'B', '\0'};

    json_string(utf8, sizeof(utf8));
    putchar('\n');

    json_string(escaped, sizeof(escaped));
    putchar('\n');

    json_string(invalid, sizeof(invalid));
    putchar('\n');

    return ferror(stdout) ? 1 : 0;
}
