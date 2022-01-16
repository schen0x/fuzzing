#include <stdio.h>
#include <stdlib.h>
#include <string.h>


long read_file(char *path, unsigned char **newbuf) {
    FILE *fp;
    if ((fp = fopen(path, "r")) == NULL) {
        fprintf(stderr, "Failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END); // fp to end
    long sz = ftell(fp); // return current pos relative to the start
    *newbuf = (unsigned char *) malloc(sz + 1);
    fseek(fp, 0L, SEEK_SET);
    fread(*newbuf, sizeof(unsigned char), sz, fp);
    (*newbuf)[sz] = 0; // NULL terminate
    fclose(fp);
    return sz;
}

// gcc file-read-strcmp.c -o file-read-strcmp
// ./file-read-strcmp file-read-strcmp.txt
int main(int argc, char *argv[])
{

    unsigned char *buf = NULL;
    long size = read_file(argv[1], &buf);

    if (strcmp(buf, "CONTENTOFTHEFILE") == 0) {
        puts("good job!");
    } else {
        puts("wrong.");
    }
    return 0;
}



