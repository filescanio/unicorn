/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to trace code with Linux code with syscall */

#include <unicorn/unicorn.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#if defined(__linux__) && defined(__x86_64__)
#include <sys/mman.h>
#define CRC32_SC_HAVE_NATIVE 1
#endif

// code to be emulated
#define X86_CODE32                                                             \
    "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x05\xcd" \
    "\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff\x68\x65\x6c\x6c" \
    "\x6f"

#define X86_CODE32_SELF                                                        \
    "\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89" \
    "\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31" \
    "\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3" \
    "\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41\x41\x41\x41\x41"

// memory address where emulation starts
#define ADDRESS 0x1000000

#define MIN(a, b) (a < b ? a : b)
// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    int r_eip;
    uint8_t tmp[16];

    printf("Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n",
           address, size);

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    printf("*** EIP = %x ***: ", r_eip);

    size = MIN(sizeof(tmp), size);
    if (!uc_mem_read(uc, address, tmp, size)) {
        uint32_t i;
        for (i = 0; i < size; i++) {
            printf("%x ", tmp[i]);
        }
        printf("\n");
    }
}

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    int32_t r_eax, r_ecx, r_eip;
    uint32_t r_edx, size;
    unsigned char buffer[256];

    // only handle Linux syscall
    if (intno != 0x80)
        return;

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);

    switch (r_eax) {
    default:
        printf(">>> 0x%x: interrupt 0x%x, EAX = 0x%x\n", r_eip, intno, r_eax);
        break;
    case 1: // sys_exit
        printf(">>> 0x%x: interrupt 0x%x, SYS_EXIT. quit!\n\n", r_eip, intno);
        uc_emu_stop(uc);
        break;
    case 4: // sys_write
        // ECX = buffer address
        uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);

        // EDX = buffer size
        uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);

        // read the buffer in
        size = MIN(sizeof(buffer) - 1, r_edx);

        if (!uc_mem_read(uc, r_ecx, buffer, size)) {
            buffer[size] = '\0';
            printf(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = "
                   "%u, content = '%s'\n",
                   r_eip, intno, r_ecx, r_edx, buffer);
        } else {
            printf(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = "
                   "%u (cannot get content)\n",
                   r_eip, intno, r_ecx, r_edx);
        }
        break;
    }
}

static void test_i386(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r_esp = ADDRESS + 0x200000; // ESP register

    printf("Emulate i386 code\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_SELF,
                     sizeof(X86_CODE32_SELF) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // handle interrupt ourself
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, hook_intr, NULL, 1, 0);

    printf("\n>>> Start tracing this Linux code\n");

    // emulate machine code in infinite time
    // err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_SELF), 0,
    // 12); <--- emulate only 12 instructions
    err =
        uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_SELF) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
               uc_strerror(err));
    }

    printf("\n>>> Emulation done.\n");

    uc_close(uc);
}

#define CRC32_SC_FILE "samples/test_crc32_sc.bin"
#define CRC32_SC_PARAM 8

/*
 * Memory layout: code and stack MUST be in separate mappings, and the stack
 * mapping MUST NOT be executable.
 *
 * Unicorn tracks writes to executable pages to detect self-modifying code: a
 * store to such a page always takes the slow path (helper call, memory region
 * lookup, translated block invalidation check) and the page is never marked
 * dirty, so every later store to it takes the slow path again. With the stack
 * in a UC_PROT_ALL mapping this applies to every push and every local
 * variable access, and this benchmark runs ~12x slower, measuring the
 * self-modifying code check instead of the emulation.
 */
#define CRC32_SC_CODE_SIZE 0x100000 // RWX: shellcode
#define CRC32_SC_STACK (ADDRESS + CRC32_SC_CODE_SIZE)
#define CRC32_SC_STACK_SIZE 0x100000 // RW, not executable: stack
// fake return address pushed on the stack; emulation stops when it is
// reached, it is in the code mapping after the shellcode
#define CRC32_SC_RET (ADDRESS + CRC32_SC_CODE_SIZE - 0x1000)
// address that is never touched by the shellcode, used for the mem hook
#define CRC32_SC_DUMMY_ADDR 0x10

enum crc32_sc_mode {
    CRC32_SC_NO_HOOKS,
    CRC32_SC_BLOCK_HOOK,
    CRC32_SC_BLOCK_MEM_HOOK,
};

struct crc32_sc_result {
    uint32_t eax;
    double elapsed;
    uint64_t blocks;
    uint64_t mem_accesses;
};

// short names used to select a single mode on the command line
static const char *const crc32_sc_mode_args[] = {"nohooks", "block",
                                                 "blockmem"};

static const char *const crc32_sc_mode_names[] = {
    "no hooks",
    "block hook",
    "block hook + mem hook on dummy address",
};

static uint64_t crc32_sc_blocks;
static uint64_t crc32_sc_mem_accesses;

static void hook_crc32_block(uc_engine *uc, uint64_t address, uint32_t size,
                             void *user_data)
{
    crc32_sc_blocks++;
}

static void hook_crc32_mem(uc_engine *uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void *user_data)
{
    crc32_sc_mem_accesses++;
    printf(">>> unexpected memory access at 0x%" PRIx64 "\n", address);
}

static void run_crc32_sc(const uint8_t *code, size_t code_size,
                         uint32_t param, enum crc32_sc_mode mode,
                         struct crc32_sc_result *res)
{
    uc_engine *uc;
    uc_err err;
    uc_hook hblock, hmem;
    uint32_t r_esp = CRC32_SC_STACK + CRC32_SC_STACK_SIZE - 0x1000;
    uint32_t r_ecx = param;
    uint32_t ret_addr = CRC32_SC_RET;
    clock_t start;

    memset(res, 0, sizeof(*res));
    printf("=== crc32 shellcode: %s ===\n", crc32_sc_mode_names[mode]);
    fflush(stdout);

    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // separate, non-executable stack: see the memory layout comment above
    uc_mem_map(uc, ADDRESS, CRC32_SC_CODE_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, CRC32_SC_STACK, CRC32_SC_STACK_SIZE,
               UC_PROT_READ | UC_PROT_WRITE);

    if (code_size > CRC32_SC_CODE_SIZE - 0x1000 ||
        uc_mem_write(uc, ADDRESS, code, code_size)) {
        printf("Failed to write emulation code to memory, quit!\n");
        uc_close(uc);
        return;
    }

    // push the return address so that the final `ret` lands on CRC32_SC_RET
    r_esp -= 4;
    uc_mem_write(uc, r_esp, &ret_addr, sizeof(ret_addr));
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);

    crc32_sc_blocks = 0;
    crc32_sc_mem_accesses = 0;

    if (mode >= CRC32_SC_BLOCK_HOOK) {
        uc_hook_add(uc, &hblock, UC_HOOK_BLOCK, hook_crc32_block, NULL, 1, 0);
    }
    if (mode >= CRC32_SC_BLOCK_MEM_HOOK) {
        uc_hook_add(uc, &hmem, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                    hook_crc32_mem, NULL, CRC32_SC_DUMMY_ADDR,
                    CRC32_SC_DUMMY_ADDR);
    }

    start = clock();
    err = uc_emu_start(uc, ADDRESS, CRC32_SC_RET, 0, 0);
    res->elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
               uc_strerror(err));
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &res->eax);
    res->blocks = crc32_sc_blocks;
    res->mem_accesses = crc32_sc_mem_accesses;
    printf(">>> done in %.3fs\n\n", res->elapsed);
    fflush(stdout);

    uc_close(uc);
}

#ifdef CRC32_SC_HAVE_NATIVE
#define CRC32_SC_NATIVE_STACK (1024 * 1024)

/*
 * Run the 32-bit shellcode natively from this 64-bit process by switching to
 * the Linux compat code segment (0x23) and back (0x33). Code, stack and the
 * mode switching stubs live in a MAP_32BIT region so they are addressable
 * from 32-bit mode.
 */
static int run_crc32_sc_native(const uint8_t *code, size_t code_size,
                               uint32_t param, struct crc32_sc_result *res)
{
    size_t region_size = CRC32_SC_NATIVE_STACK + 0x1000 + code_size;
    uint8_t *region, *p;
    uint32_t base, saved_rsp, enter64, thunk32, back64, code32, stack_top;
    uint32_t (*enter)(uint32_t);
    clock_t start;

    memset(res, 0, sizeof(*res));
    printf("=== crc32 shellcode: native ===\n");
    fflush(stdout);

    region = mmap(NULL, region_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (region == MAP_FAILED) {
        printf("Failed to mmap native region\n\n");
        return -1;
    }

    base = (uint32_t)(uintptr_t)region;
    stack_top = base + CRC32_SC_NATIVE_STACK;
    saved_rsp = stack_top;
    enter64 = stack_top + 0x10;
    thunk32 = stack_top + 0x80;
    back64 = stack_top + 0xc0;
    code32 = stack_top + 0x1000;
    memcpy(region + (code32 - base), code, code_size);

#define EMIT(...)                                                              \
    do {                                                                       \
        static const uint8_t b_[] = {__VA_ARGS__};                             \
        memcpy(p, b_, sizeof(b_));                                             \
        p += sizeof(b_);                                                       \
    } while (0)
#define EMIT32(v)                                                              \
    do {                                                                       \
        uint32_t v_ = (v);                                                     \
        memcpy(p, &v_, 4);                                                     \
        p += 4;                                                                \
    } while (0)

    // 64-bit: save callee-saved regs and rsp, switch stack, far return to
    // the 32-bit thunk
    p = region + (enter64 - base);
    EMIT(0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57);
    EMIT(0x48, 0x89, 0x24, 0x25); // mov [saved_rsp], rsp
    EMIT32(saved_rsp);
    EMIT(0xbc); // mov esp, stack_top
    EMIT32(stack_top);
    EMIT(0x89, 0xf9);       // mov ecx, edi
    EMIT(0x6a, 0x23);       // push 0x23
    EMIT(0x68);             // push thunk32
    EMIT32(thunk32);
    EMIT(0x48, 0xcb);       // lretq

    // 32-bit: set up data segments, call the shellcode, far return to 64-bit
    p = region + (thunk32 - base);
    EMIT(0x6a, 0x2b, 0x1f); // push 0x2b; pop ds
    EMIT(0x6a, 0x2b, 0x07); // push 0x2b; pop es
    EMIT(0xba);             // mov edx, code32
    EMIT32(code32);
    EMIT(0xff, 0xd2);       // call edx
    EMIT(0x6a, 0x33);       // push 0x33
    EMIT(0x68);             // push back64
    EMIT32(back64);
    EMIT(0xcb);             // retf

    // 64-bit: restore rsp and callee-saved regs, return eax to the caller
    p = region + (back64 - base);
    EMIT(0x48, 0x8b, 0x24, 0x25); // mov rsp, [saved_rsp]
    EMIT32(saved_rsp);
    EMIT(0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5d, 0x5b, 0xc3);

#undef EMIT
#undef EMIT32

    enter = (uint32_t(*)(uint32_t))(uintptr_t)enter64;

    start = clock();
    res->eax = enter(param);
    res->elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;

    printf(">>> done in %.3fs\n\n", res->elapsed);
    fflush(stdout);

    munmap(region, region_size);
    return 0;
}
#endif

static uint8_t *load_crc32_sc(const char *path, long *code_size)
{
    FILE *f;
    uint8_t *code;

    f = fopen(path, "rb");
    if (!f) {
        printf("Failed to open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    *code_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    code = malloc(*code_size);
    if (!code || fread(code, 1, *code_size, f) != (size_t)*code_size) {
        printf("Failed to read %s\n", path);
        free(code);
        fclose(f);
        return NULL;
    }
    fclose(f);

    return code;
}

#ifdef CRC32_SC_HAVE_NATIVE
static void test_crc32_sc_native(const char *path, uint32_t param)
{
    uint8_t *code;
    long code_size;
    struct crc32_sc_result res;

    code = load_crc32_sc(path, &code_size);
    if (!code) {
        return;
    }

    printf("Run crc32 shellcode natively from %s (%ld bytes)\n\n", path,
           code_size);

    if (run_crc32_sc_native(code, code_size, param, &res) == 0) {
        printf(">>> native ECX = %u, EAX = 0x%08x, time = %.3fs\n", param,
               res.eax, res.elapsed);
    }

    free(code);
}
#endif

// @only: NULL runs all modes, otherwise "native" or one of crc32_sc_mode_args
static void test_crc32_sc(const char *path, uint32_t param, const char *only)
{
    uint8_t *code;
    long code_size;
    struct crc32_sc_result res[3];
    int ran[3] = {0};
    int i;
#ifdef CRC32_SC_HAVE_NATIVE
    struct crc32_sc_result native_res;
    int native_ok = 0;
#endif

    code = load_crc32_sc(path, &code_size);
    if (!code) {
        return;
    }

    printf("Emulate crc32 shellcode from %s (%ld bytes)\n\n", path, code_size);

#ifdef CRC32_SC_HAVE_NATIVE
    if (!only || !strcmp(only, "native")) {
        native_ok =
            run_crc32_sc_native(code, code_size, param, &native_res) == 0;
    }
#endif
    for (i = CRC32_SC_NO_HOOKS; i <= CRC32_SC_BLOCK_MEM_HOOK; i++) {
        if (!only || !strcmp(only, crc32_sc_mode_args[i])) {
            run_crc32_sc(code, code_size, param, i, &res[i]);
            ran[i] = 1;
        }
    }

    printf("=== Summary (ECX = %u) ===\n", param);
#ifdef CRC32_SC_HAVE_NATIVE
    if (native_ok) {
        printf(">>> %-40s EAX = 0x%08x  time = %8.3fs\n", "native",
               native_res.eax, native_res.elapsed);
    }
#endif
    for (i = CRC32_SC_NO_HOOKS; i <= CRC32_SC_BLOCK_MEM_HOOK; i++) {
        if (!ran[i]) {
            continue;
        }
        printf(">>> %-40s EAX = 0x%08x  time = %8.3fs", crc32_sc_mode_names[i],
               res[i].eax, res[i].elapsed);
        if (i >= CRC32_SC_BLOCK_HOOK) {
            printf("  block hooks = %" PRIu64, res[i].blocks);
        }
        if (i >= CRC32_SC_BLOCK_MEM_HOOK) {
            printf("  mem hooks = %" PRIu64, res[i].mem_accesses);
        }
        printf("\n");
    }

    free(code);
}

int main(int argc, char **argv, char **envp)
{
    if (argc >= 2) {
        if (!strcmp(argv[1], "-32")) {
            test_i386();
        } else if (!strcmp(argv[1], "-crc32")) {
            test_crc32_sc(argc >= 3 ? argv[2] : CRC32_SC_FILE,
                          argc >= 4 ? strtoul(argv[3], NULL, 0)
                                    : CRC32_SC_PARAM,
                          argc >= 5 ? argv[4] : NULL);
#ifdef CRC32_SC_HAVE_NATIVE
        } else if (!strcmp(argv[1], "-crc32-native")) {
            test_crc32_sc_native(argc >= 3 ? argv[2] : CRC32_SC_FILE,
                                 argc >= 4 ? strtoul(argv[3], NULL, 0)
                                           : CRC32_SC_PARAM);
#endif
        } else if (!strcmp(argv[1], "-h")) {
            printf("Syntax: %s <-32|-crc32 [file [ecx "
                   "[native|nohooks|block|blockmem]]]|-crc32-native [file "
                   "[ecx]]>\n",
                   argv[0]);
        }
    } else {
        test_i386();
    }

    return 0;
}
