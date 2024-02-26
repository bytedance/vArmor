
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

__attribute__ ((constructor)) void foo(void)
{
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd == -1 ) {
        printf("HAX: can't open /proc/self/exe\n");
        return;
    }
    printf("HAX: fd is %d\n", fd);

    char *argv2[3];
    argv2[0] = strdup("/stage2");
    char buf[128];
    snprintf(buf, 128, "/proc/self/fd/%d", fd);
    argv2[1] = buf;
    argv2[2] = 0;
    execve("/stage2", argv2, NULL);
}

