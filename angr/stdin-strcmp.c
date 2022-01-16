#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[40];
    scanf("%40s", buf);
    if (strcmp(argv[1], "argument") == 0 && strcmp(buf, "standardinput") == 0) {
        puts("good job!");
    } else {
        puts("wrong.");
    }
    return 0;
}

