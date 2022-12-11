#ifndef inject_h
#define inject_h

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>

#include <alloca.h>

extern void _pthread_set_self(void* ctx);

extern void ldr_shellcode(void);
extern void ldr_shellcode_data(void);
extern void ldr_shellcode_end(void);

struct s_ldr_data {
    void *mach_thread_self;
    void *thread_terminate;
    void *dlopen;
    void *dlsym;
    char libpath[PATH_MAX];
} __attribute__((packed));

typedef struct s_ldr_data ldr_data_t;

int injectDylib(int pid, const char *lib);

#endif /* inject_h */
