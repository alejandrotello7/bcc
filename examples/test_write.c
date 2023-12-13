#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>

int main() {
    // Get the PID of the current process
    pid_t pid = getpid();
    printf("My PID: %d\n", pid);

    // Wait for X seconds (replace X with the desired number)
    int wait_time = 20;
    printf("Waiting for %d seconds...\n", wait_time);
    sleep(wait_time);

    // Open a file called test.txt
    const char* file_path = "/home/atello/bcc/examples/test2.txt";
    FILE* file = fopen(file_path, "w");
    int fd = fileno(file);
    sleep(5);
    // printf("File Descriptor: %d\n", fd);
    fprintf(file, "Hello(2), this is a test file!\n");

    // fclose(file);
    // printf("File '%s' created.\n", file_path);

    return 0;
}
