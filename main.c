#include <stdio.h>
#include <string.h>

void* secure_malloc(size_t size);
void secure_free(void *ptr);

int main(void) {
    printf("[*] Allocating safe buffer via secure_malloc...\n");
    char *buffer = (char*)secure_malloc(16);
    if (!buffer) {
        return 1;
    }

    strcpy(buffer, "NormalPayload");
    printf("[*] Buffer contents: %s\n", buffer);

    printf("[*] Simulating linear heap overflow (writing past allocated bounds)...\n");
    // Writing 24 bytes into a 16-byte allocated region
    memcpy(buffer, "MaliciousOverflowPayload!!!", 28); 

    printf("[*] Attempting secure_free to trigger integrity check...\n");
    secure_free(buffer);

    // This point should never be reached
    printf("[!] Error: Allocator failed to catch corruption.\n");
    return 0;
}
