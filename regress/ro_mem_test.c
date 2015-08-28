#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <unicorn/unicorn.h>

const uint8_t PROGRAM[] =  
"\xeb\x1a\x58\x83\xc0\x04\x83\xe0\xfc\x83\xc0\x01\xc7\x00\x78\x56"
"\x34\x12\x83\xc0\x07\xc7\x00\x21\x43\x65\x87\x90\xe8\xe1\xff\xff"
"\xff" "xxxxAAAAxxxBBBB";
// total size: 33 bytes

/*
   jmp short bottom
top:
pop eax
add eax, 4
and eax, 0xfffffffc
add eax, 1             ; unaligned
mov dword [eax], 0x12345678  ; try to write into code section
add eax, 7             ; aligned
mov dword [eax], 0x87654321  ; try to write into code section
nop
bottom:
call top
 */

// callback for tracing instruction
static void hook_code(uch handle, uint64_t address, uint32_t size, void *user_data)
{
    uint32_t esp;
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    uc_reg_read(handle, UC_X86_REG_ESP, &esp);
    printf(">>> --- ESP is 0x%x\n", esp);

}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uch handle, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    uint32_t esp;
    uc_reg_read(handle, UC_X86_REG_ESP, &esp);

    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_WRITE:
            //if this is a push, esp has not been adjusted yet
            if (esp == (address + size)) {
                uint32_t upper;
                upper = (esp + 0xfff) & ~0xfff;
                printf(">>> Stack appears to be missing at 0x%"PRIx64 ", allocating now\n", address);
                // map this memory in with 2MB in size
                uc_mem_map_ex(handle, upper - 0x8000, 0x8000, UC_PROT_READ | UC_PROT_WRITE);
                // return true to indicate we want to continue
                return true;
            }
            printf(">>> Missing memory is being WRITTEN at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                    address, size, value);
            return false;
        case UC_MEM_WRITE_RO:
            printf(">>> RO memory is being WRITTEN at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                    address, size, value);
            return false;
    }
}


#define STACK 0x500000
#define STACK_SIZE 0x5000

int main(int argc, char **argv, char **envp)
{
    uch handle, trace1, trace2;
    uc_err err;
    uint8_t bytes[8];
    uint32_t esp;
    int result;
    int map_stack = 0;

    if (argc == 2 && strcmp(argv[1], "--map-stack") == 0) {
        map_stack = 1;
    }

    printf("Memory mapping test\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &handle);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return 1;
    }

    uc_mem_map(handle, 0x100000, 0x1000);
    uc_mem_map(handle, 0x200000, 0x2000);
    uc_mem_map(handle, 0x300000, 0x3000);
    uc_mem_map_ex(handle, 0x400000, 0x4000, UC_PROT_READ);

    if (map_stack) {
        printf("Pre-mapping stack\n");
        uc_mem_map_ex(handle, STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    }
    else {
        printf("Mapping stack on first invalid memory access\n");
    }

    esp = STACK + STACK_SIZE;

    uc_reg_write(handle, UC_X86_REG_ESP, &esp); 

    // write machine code to be emulated to memory
    if (uc_mem_write(handle, 0x400000, PROGRAM, sizeof(PROGRAM))) {
        printf("Failed to write emulation code to memory, quit!\n");
        return 2;
    }
    else {
        printf("Allowed to write to read only memory via uc_mem_write\n");
    }

    //uc_hook_add(handle, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)0x400000, (uint64_t)0x400fff);

    // intercept invalid memory events
    uc_hook_add(handle, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL);

    // emulate machine code in infinite time
    printf("BEGIN execution - 1\n");
    err = uc_emu_start(handle, 0x400000, 0x400000 + sizeof(PROGRAM), 0, 10);
    if (err) {
        printf("Expected failue on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }
    else {
        printf("UNEXPECTED uc_emu_start returned UC_ERR_OK\n");
    }
    printf("END execution - 1\n");

    // emulate machine code in infinite time
    printf("BEGIN execution - 2\n");
    uint32_t eax = 0x40002C;
    uc_reg_write(handle, UC_X86_REG_EAX, &eax); 
    err = uc_emu_start(handle, 0x400015, 0x400000 + sizeof(PROGRAM), 0, 2);
    if (err) {
        printf("Expected failure on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }
    else {
        printf("UNEXPECTED uc_emu_start returned UC_ERR_OK\n");
    }
    printf("END execution - 2\n");

    printf("Verifying content at 0x400025 is unchanged\n");
    if (!uc_mem_read(handle, 0x400025, bytes, 4)) {
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", (uint32_t)0x400025, *(uint32_t*) bytes);
        if (0x41414141 != *(uint32_t*) bytes) {
            printf("ERROR content in read only memory changed\n");
        }
        else {
            printf("SUCCESS content in read only memory unchanged\n");
        }
    }
    else {
        printf(">>> Failed to read 4 bytes from [0x%x]\n", (uint32_t)(esp - 4));
        return 4;
    }

    printf("Verifying content at 0x40002C is unchanged\n");
    if (!uc_mem_read(handle, 0x40002C, bytes, 4)) {
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", (uint32_t)0x40002C, *(uint32_t*) bytes);
        if (0x42424242 != *(uint32_t*) bytes) {
            printf("ERROR content in read only memory changed\n");
        }
        else {
            printf("SUCCESS content in read only memory unchanged\n");
        }
    }
    else {
        printf(">>> Failed to read 4 bytes from [0x%x]\n", (uint32_t)(esp - 4));
        return 4;
    }

    printf("Verifying content at bottom of stack is readable and correct\n");
    if (!uc_mem_read(handle, esp - 4, bytes, 4)) {
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", (uint32_t)(esp - 4), *(uint32_t*) bytes);
    }
    else {
        printf(">>> Failed to read 4 bytes from [0x%x]\n", (uint32_t)(esp - 4));
        return 4;
    }

    uc_close(&handle);

    return 0;
}