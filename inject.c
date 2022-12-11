//# coding by k
#include "inject.h"

void
init_shellcode_buffer(void *p, const char *libpath)
{
    size_t ldr_shellcode_size = ldr_shellcode_end - ldr_shellcode;
    size_t ldr_data_offset = ldr_shellcode_data - ldr_shellcode;
    
    ldr_data_t *data = (ldr_data_t *)(p + ldr_data_offset);

    memcpy(p, ldr_shellcode, ldr_shellcode_size);
    
    data->mach_thread_self = (void *)mach_thread_self;
    data->thread_terminate = (void *)thread_terminate;
    data->dlopen = (void *)dlopen;
    data->dlsym = (void *)dlsym;
    
    strcpy(data->libpath, libpath);
}


int
injectDylib(int pid, const char *libpath)
{
    task_t task_port;
    kern_return_t kr;
    
    vm_address_t remote_buffer_addr = 0;
    vm_address_t remote_stack_base = 0;
    vm_address_t remote_ldr_addr = 0;
    
    size_t remote_stack_size = 4 * 1024 * 1024;
    
    size_t ldr_shellcode_size = ldr_shellcode_end - ldr_shellcode;
    void *ldr_buffer = alloca(ldr_shellcode_size);
    
    init_shellcode_buffer(ldr_buffer, libpath);
    
    kr = task_for_pid(mach_task_self(), pid, &task_port);
    
    if (kr != KERN_SUCCESS) {
        fprintf (stderr, "Unable to call task_for_pid on pid %d: %s. Cannot continue!\n", pid, mach_error_string(kr));
        return -1;
    }
    
    kr = vm_allocate(task_port, &remote_buffer_addr, remote_stack_size, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return -2;
    }
    
    kr = vm_allocate(task_port, &remote_stack_base, remote_stack_size, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return -2;
    }

    kr = vm_allocate(task_port, &remote_ldr_addr, ldr_shellcode_size, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
        return -3;
    }
    
    kr = vm_write(
        task_port,
        remote_ldr_addr,
        (vm_address_t)ldr_buffer,
        (mach_msg_type_number_t)ldr_shellcode_size
    );

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
        return -3;
    }

    kr  = vm_protect(task_port, remote_ldr_addr, ldr_shellcode_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to set memory permissions for remote thread: Error %s\n", mach_error_string(kr));
        return (-4);
    }
    
    kr  = vm_protect(task_port, remote_stack_base, remote_stack_size, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to set memory permissions 2 for remote thread: Error %s\n", mach_error_string(kr));
        return (-4);
    }

    uint64_t remote_stack_middle = remote_stack_base + (remote_stack_size / 2);
    
    thread_state_flavor_t flavor;
    mach_msg_type_number_t count;
    
    flavor = ARM_THREAD_STATE64;
    count = ARM_THREAD_STATE64_COUNT;
    arm_thread_state64_t state = { };
    
    state.__x[0] = remote_buffer_addr;
    state.__sp = remote_stack_middle;
    state.__pc = remote_ldr_addr;
    
    thread_state_t state_ptr = (thread_state_t)&state;
    thread_t thread_port;
    
    kr = thread_create_running(task_port, flavor, state_ptr, count, &thread_port);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
        return (-3);
    }
    
    return 0;

}
