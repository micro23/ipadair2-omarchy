#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <TargetConditionals.h>
#include <errno.h>
#include <string.h>
/* Adapted from HoolockLinux/docs tools/resize.c, commit
 * 23ebe1fbc375599221553a7e1815e5de182a6b42. Retain LICENSE-Hoolock-MIT.txt.
 * J81 addition: probe-only default and an exact, explicit execute target.
 */

#if TARGET_OS_OSX || TARGET_OS_SIMULATOR
#define APFS_FW_PATH "/System/Library/PrivateFrameworks/APFS.framework/Versions/A/APFS"
#else
#define APFS_FW_PATH "/System/Library/PrivateFrameworks/APFS.framework/APFS"
#endif

int (*APFSContainerResize)(const char *bsdname, uint64_t newSize);

int main(int argc, const char * argv[]) {
    size_t new_size;
    char* endptr;

    int probe = argc == 2 && !strcmp(argv[1], "--probe");
    if (!probe && (argc != 5 || strcmp(argv[1], "--execute-approved-j81-shrink") ||
                   strcmp(argv[2], "disk0s1") || strcmp(argv[3], "17179869184") ||
                   strcmp(argv[4], "J81-16GiB-APFS"))) {
        fprintf(stderr, "usage: %s --probe\n", argv[0]);
        fprintf(stderr, "or: %s --execute-approved-j81-shrink disk0s1 17179869184 J81-16GiB-APFS\n", argv[0]);
        return -1;
    }

    errno = 0;
    new_size = probe ? 0 : strtoull(argv[3], &endptr, 10);
    if (!probe && (errno || *endptr || new_size != 17179869184ULL)) {
        fprintf(stderr, "Invalid new size given\n");
        return -1;
    }

    void *handle = dlopen(APFS_FW_PATH, RTLD_LAZY);

    if (!handle) {
        fprintf(stderr, "Could not load APFS.framework: %s", dlerror());
        return -1;
    }

    APFSContainerResize = dlsym(handle, "APFSContainerResize");
    if (!APFSContainerResize) {
        fprintf(stderr, "Function APFSContainerResize not found: %s", dlerror());
        dlclose(handle);
        return -1;
    }

    if (probe) {
        puts("PASS: Apple APFS framework and resize entry point available; no resize requested.");
        dlclose(handle);
        return 0;
    }

    printf("About to resize %s to %s bytes; device may become unresponsive during the online resize.\n", argv[2], argv[3]);

    int result = APFSContainerResize(argv[2], new_size);
    if (result != 0) {
        fprintf(stderr,"APFSContainerResize failed: %d: %s\n", result, mach_error_string(result));
        return -1;
    }

    printf("The operation completed successfully\n");

    dlclose(handle);
    return 0;
}
