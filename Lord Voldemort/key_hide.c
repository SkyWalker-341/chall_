#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define KEY_SIZE 64  // Adjust based on your key size
#define KEY_FILE "keyfile.txt"

void *secure_memory = NULL;

// Function to securely load key from file
void load_key_from_file(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening key file");
        exit(EXIT_FAILURE);
    }

    // Read key into protected memory
    if (read(fd, secure_memory, KEY_SIZE) <= 0) {
        perror("Error reading key");
        close(fd);
        exit(EXIT_FAILURE);
    }
    
    close(fd);
}

// Signal handler to reveal the key when process is killed
void handle_sigterm(int signum) {
    printf("\nProcess killed! Revealing the key...\n");

    // Restore memory permissions to allow reading
    mprotect(secure_memory, KEY_SIZE, PROT_READ | PROT_WRITE);

    // Print the key
    printf("Secret Key: %s\n", (char *)secure_memory);

    // Clear the memory before exit
    memset(secure_memory, 0, KEY_SIZE);
    exit(0);
}

int main() {
    // Allocate secure memory
    secure_memory = mmap(NULL, KEY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (secure_memory == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // Prevent swapping to disk
    if (mlock(secure_memory, KEY_SIZE) != 0) {
        perror("mlock");
        exit(EXIT_FAILURE);
    }

    // Load key from file into protected memory
    load_key_from_file(KEY_FILE);

    // Protect memory (Make it unreadable)
    mprotect(secure_memory, KEY_SIZE, PROT_NONE);

    // Handle process termination (SIGTERM)
    signal(SIGTERM, handle_sigterm);

    printf("Process running... Key is protected!\n");
    printf("Kill the process (kill -15 <PID>) to retrieve the key.\n");

    // Keep process running
    while (1) {
        sleep(1);
    }

    return 0;
}
