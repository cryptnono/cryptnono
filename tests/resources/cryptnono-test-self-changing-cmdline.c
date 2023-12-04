#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main (int argc, char* argv[])
{
    printf("pid: %i\n", getpid());
    sleep(5);
    snprintf(argv[0], strlen(argv[0]), "cryptnono.banned.string1");
    // In the tests we set --scan-existing 10 seconds so this should be killed
    // If it's not then we'll know because this will return 0
    sleep(15);
    return 0;
}
