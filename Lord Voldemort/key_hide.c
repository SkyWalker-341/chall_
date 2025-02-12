// // #include <stdio.h>
// // #include <stdlib.h>
// // #include <string.h>
// // #include <sys/mman.h>
// // #include <signal.h>
// // #include <unistd.h>
// // #include <fcntl.h>
// // #include <sys/stat.h>

// // #define KEY_SIZE 64  // Adjust based on your key size
// // #define KEY_FILE "keyfile.txt"

// // void *secure_memory = NULL;

// // // Function to securely load key from file
// // void load_key_from_file(const char *filename) {
// //     int fd = open(filename, O_RDONLY);
// //     if (fd < 0) {
// //         perror("Error opening key file");
// //         exit(EXIT_FAILURE);
// //     }

// //     // Read key into protected memory
// //     if (read(fd, secure_memory, KEY_SIZE) <= 0) {
// //         perror("Error reading key");
// //         close(fd);
// //         exit(EXIT_FAILURE);
// //     }
    
// //     close(fd);
// // }

// // // Signal handler to reveal the key when process is killed
// // void handle_sigterm(int signum) {
// //     printf("\nProcess killed! Revealing the key...\n");

// //     // Restore memory permissions to allow reading
// //     mprotect(secure_memory, KEY_SIZE, PROT_READ | PROT_WRITE);

// //     // Print the key
// //     printf("Secret Key: %s\n", (char *)secure_memory);

// //     // Clear the memory before exit
// //     memset(secure_memory, 0, KEY_SIZE);
// //     exit(0);
// // }

// // int main() {
// //     // Allocate secure memory
// //     secure_memory = mmap(NULL, KEY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// //     if (secure_memory == MAP_FAILED) {
// //         perror("mmap");
// //         exit(EXIT_FAILURE);
// //     }

// //     // Prevent swapping to disk
// //     if (mlock(secure_memory, KEY_SIZE) != 0) {
// //         perror("mlock");
// //         exit(EXIT_FAILURE);
// //     }

// //     // Load key from file into protected memory
// //     load_key_from_file(KEY_FILE);

// //     // Protect memory (Make it unreadable)
// //     mprotect(secure_memory, KEY_SIZE, PROT_NONE);

// //     // Handle process termination (SIGTERM)
// //     signal(SIGTERM, handle_sigterm);

// //     printf("Process running... Key is protected!\n");
// //     printf("Kill the process (kill -15 <PID>) to retrieve the key.\n");

// //     // Keep process running
// //     while (1) {
// //         sleep(1);
// //     }

// //     return 0;
// // }

// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <sys/mman.h>
// #include <signal.h>
// #include <string.h>

// #define KEY_SIZE 64  
// char *key_buffer = NULL;

// void handle_sigterm(int signum) {
//     printf("\nProcess killed! Revealing the key...\n");

//     // Restore memory access
//     mprotect(key_buffer, KEY_SIZE, PROT_READ | PROT_WRITE);

//     // Print the key
//     printf("Secret Key: %s\n", key_buffer);

//     // Clear memory before exit
//     memset(key_buffer, 0, KEY_SIZE);
//     munlock(key_buffer, KEY_SIZE);
//     free(key_buffer);
    
//     exit(0);
// }

// int main(void) {
//     int fd = open(".key.key", O_RDONLY);
//     if (fd < 0) {
//         perror("open");
//         exit(EXIT_FAILURE);
//     }

//     // Allocate a buffer for the key
//     key_buffer = (char *)malloc(KEY_SIZE);
//     if (!key_buffer) {
//         perror("malloc");
//         close(fd);
//         exit(EXIT_FAILURE);
//     }

//     // Read the key into memory
//     ssize_t bytes_read = read(fd, key_buffer, KEY_SIZE);
//     if (bytes_read < 0) {
//         perror("read");
//         close(fd);
//         exit(EXIT_FAILURE);
//     }

//     // Unlink (remove) the file
//     if (unlink(".key.key") != 0) {
//         perror("unlink");
//     }

//     printf("Key loaded into memory and file removed.\n");

//     // Lock the key in memory to prevent swapping
//     if (mlock(key_buffer, KEY_SIZE) != 0) {
//         perror("mlock");
//     }

//     // Protect memory so it can't be read until process is killed
//     mprotect(key_buffer, KEY_SIZE, PROT_NONE);

//     // Set up a signal handler to reveal the key on termination
//     signal(SIGTERM, handle_sigterm);
//     signal(SIGINT, handle_sigterm);

//     // Keep the process running
//     while (1) {
//         sleep(1);
//     }

//     close(fd);
//     return 0;
// }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#define FILE_PATH "hidden_file.txt"
#define BACKUP_PATH "restored_file.txt"

void *file_memory = NULL;
size_t file_size = 0;

void restore_file(int signum) {
    printf("\nSignal received (%d), restoring file...\n", signum);
    
    // Write back the file
    int fd = open(BACKUP_PATH, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("Failed to create backup file");
        exit(EXIT_FAILURE);
    }

    if (write(fd, file_memory, file_size) != file_size) {
        perror("Failed to restore file contents");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
    printf("File restored as '%s'.\n", BACKUP_PATH);

    // Cleanup and exit
    munmap(file_memory, file_size);
    exit(EXIT_SUCCESS);
}

int main() {
    int fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("Failed to get file size");
        close(fd);
        return EXIT_FAILURE;
    }
    
    file_size = st.st_size;
    
    // Map the file into memory
    file_memory = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (file_memory == MAP_FAILED) {
        perror("Failed to mmap file");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);

    // Delete the original file
    if (unlink(FILE_PATH) < 0) {
        perror("Failed to delete file");
        return EXIT_FAILURE;
    }

    printf("File '%s' loaded into memory and deleted.\n", FILE_PATH);
    printf("Process running... (PID: %d)\n", getpid());

    // Set up signal handlers
    signal(SIGTERM, restore_file);
    signal(SIGINT, restore_file);

    // Keep process running
    while (1) {
        sleep(1);
    }

    return EXIT_SUCCESS;
}

