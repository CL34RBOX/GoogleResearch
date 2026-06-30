#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#include <unistd.h>
#endif

// OMNIBUS Secure Allocator Definitions
#define CANARY_SIZE 8
static uint8_t global_canary[CANARY_SIZE] = {0};
static bool canary_initialized = false;

// Internal metadata structure stored immediately before the user payload
typedef struct {
    size_t requested_size;
    uint8_t canary[CANARY_SIZE];
} __attribute__((packed)) chunk_metadata_t;

/**
 * Initializes the global cryptographic canary using system-level entropy.
 */
static void secure_init_canary(void) {
    if (canary_initialized) return;

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, global_canary, CANARY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        abort(); // Fail closed if entropy generation fails
    }
#else
    if (getrandom(global_canary, CANARY_SIZE, 0) != CANARY_SIZE) {
        // Fallback to /dev/urandom if getrandom block is interrupted
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(global_canary, 1, CANARY_SIZE, f) != CANARY_SIZE) {
            abort();
        }
        if (f) fclose(f);
    }
#endif
    canary_initialized = true;
}

/**
 * Hardened Allocation Wrapper
 * Allocates: [chunk_metadata_t] [user_payload] [canary_footer]
 */
void* secure_malloc(size_t size) {
    if (size == 0 || size > (SIZE_MAX - sizeof(chunk_metadata_t) - CANARY_SIZE)) {
        return NULL;
    }

    if (!canary_initialized) {
        secure_init_canary();
    }

    size_t total_size = sizeof(chunk_metadata_t) + size + CANARY_SIZE;
    uint8_t *raw_block = (uint8_t*)malloc(total_size);
    if (!raw_block) {
        return NULL;
    }

    // Populate metadata header
    chunk_metadata_t *meta = (chunk_metadata_t*)raw_block;
    meta->requested_size = size;
    memcpy(meta->canary, global_canary, CANARY_SIZE);

    // Calculate payloads and footers
    uint8_t *user_payload = raw_block + sizeof(chunk_metadata_t);
    uint8_t *canary_footer = user_payload + size;

    // Place the trailing canary to detect linear overflows
    memcpy(canary_footer, global_canary, CANARY_SIZE);

    return (void*)user_payload;
}

/**
 * Hardened Deallocation Wrapper
 * Validates header integrity and trailing canary before executing free()
 */
void secure_free(void *ptr) {
    if (!ptr) return;

    // Recover metadata block from the user pointer
    uint8_t *user_payload = (uint8_t*)ptr;
    chunk_metadata_t *meta = (chunk_metadata_t*)(user_payload - sizeof(chunk_metadata_t));

    // Calculate trailing canary location
    uint8_t *canary_footer = user_payload + meta->requested_size;

    // Verify header canary and footer canary against global secret
    int header_corrupt = memcmp(meta->canary, global_canary, CANARY_SIZE);
    int footer_corrupt = memcmp(canary_footer, global_canary, CANARY_SIZE);

    if (header_corrupt != 0 || footer_corrupt != 0) {
        // Integrity violation detected: print alert and terminate immediately to prevent exploitation
        fprintf(stderr, "[!] CRITICAL: Heap metadata corruption detected! Execution aborted.\n");
        abort();
    }

    // Explicitly zero out metadata and data payload to prevent Use-After-Free (UAF) info leaks
    size_t total_size = sizeof(chunk_metadata_t) + meta->requested_size + CANARY_SIZE;
    uint8_t *raw_block = (uint8_t*)meta;
    memset(raw_block, 0, total_size);

    free(raw_block);
}
