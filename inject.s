// code by k
.text
.align 2
.global _ldr_shellcode
.global _ldr_shellcode_data
.global _ldr_shellcode_end

.macro .bytes n
    .rept \n
        .byte 0x0
    .endr
.endm

_ldr_shellcode:
    // x0 = thread_buffer
    bl _pthread_set_self

    // invoke thread_create_from_mach_thread
    ldr x7, __dlsym
    mov x0, #-2
    adr x1, __s_pthread_create_from_mach_thread
    blr x7
    mov x8, x0

    mov x3, x0
    adr x2, _cthread0
    mov x1, #0
    add x0, sp, #8
    blr x8

    ldr x7, __mach_thread_self
    blr x7
    ldr x8, __thread_terminate
    blr x8

    brk #0xffff


_cthread0:
    // invoke dlopen(libpath)
    adr x0, __libpath
    mov x1, #0
    ldr x8, __dlopen
    blr x8

    ldr x7, __mach_thread_self
    blr x7
    ldr x8, __thread_terminate
    blr x8

    ldr x7, __dlsym
    mov x0, #-2
    adr x1, __s_pthread_exit
    blr x7

    mov x8, x0
    mov x0, xzr
    blr x8

    brk #0xffff


_pthread_set_self:
    mov    x8, x0

_thread_selfid:
    mov x16, #0x174
    svc #0xffff

    str    x0, [x8, #0xd8]
    add    x0, x8, #0xe0

_thread_set_tsd_base:
    mov x3, #0x2
    mov x16, #0x80000000
    svc #0xffff

    ret


__ldr_shellcode_const:
.long 0x00, 0x00

__s_pthread_create_from_mach_thread:
.asciz "pthread_create_from_mach_thread"
.long 0x00

__s_pthread_exit:
.ascii "pthread_exit"
.long 0x00

_ldr_shellcode_data:

__mach_thread_self:
.long 0x00, 0x00

__thread_terminate:
.long 0x00, 0x00

__dlopen:
.long 0x00, 0x00

__dlsym:
.long 0x00, 0x00

__libpath:
.bytes 1024

_ldr_shellcode_end:
ret
