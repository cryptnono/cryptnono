#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * This provides an executable to test whether execwhacker detects processes that
 * were missed by BPF.
 *
 * execwhacker should be run with arguments `--config /example/config.json --scan-existing 10`
 *
 * This program should be compiled to an executable named `cryptnono-test-self-changing-cmdline`
 * which means it should be allowed by execwhacker.
 *
 * After a few seconds the executable overwrites it's argv[0] to the banned string
 * `cryptnono.banned.string1` which means it should be killed after a short while (less than 10
 * seconds) by the non-BPF scanner.
 *
 * If not it will exit with code 0, and the test wrapper should report an error.
 */
int main (int argc, char* argv[])
{
    printf("pid: %i\n", getpid());
    sleep(5);
    snprintf(argv[0], strlen(argv[0]), "cryptnono.banned.string1");
    sleep(15);
    return 0;
}
