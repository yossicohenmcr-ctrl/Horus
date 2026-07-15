.section .multiboot, "a"
.align 8

multiboot_header_start:
    .long 0xe85250d6
    .long 0
    .long multiboot_header_end - multiboot_header_start
    .long -(0xe85250d6 + 0 + (multiboot_header_end - multiboot_header_start))
    .word 0
    .word 0
    .long 8
multiboot_header_end:

.section .text
.code32
.global _start
.extern kernel_main

_start:
    movl $stack_top, %esp

    movl %cr4, %eax
    orl  $(1 << 5), %eax
    movl %eax, %cr4

    movl $pml4, %edi
    movl %edi, %cr3

    xorl %eax, %eax
    movl $pml4, %edi
    movl $12288, %ecx
    rep stosl

    movl $pdpt, %eax
    orl  $0x3, %eax
    movl %eax, pml4

    movl $pd, %eax
    orl  $0x3, %eax
    movl %eax, pdpt

    movl $pd, %edi
    movl $0x00000000, %ebx
    movl $512, %ecx

1:
    movl %ebx, %eax
    andl $0xFFE00000, %eax
    orl  $0x00000083, %eax
    movl $0x00000000, %edx
    movl %eax, 0(%edi)
    movl %edx, 4(%edi)
    addl $0x200000, %ebx
    addl $8, %edi
    loop 1b

    movl $high_pdpt, %eax
    orl  $0x3, %eax
    movl %eax, pml4 + (511 * 8)

    movl $pd, %eax
    orl  $0x3, %eax
    movl %eax, high_pdpt + (2 * 8)

    movl $0xC0000080, %ecx
    rdmsr
    orl  $((1 << 8) | (1 << 11)), %eax   /* EFER.LME | EFER.NXE (honor NX bit) */
    wrmsr

    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    lgdt gdt64_ptr32
    ljmp $0x08, $long_mode_entry

.section .text
.code64
long_mode_entry:
    lgdt (gdt64_ptr)

    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movabs $stack_top, %rsp

    movq %cr4, %rax
    orq  $(1 << 9), %rax
    movq %rax, %cr4

    movq %cr0, %rax
    andq $~(1 << 2), %rax
    orq  $(1 << 1), %rax
    movq %rax, %cr0

    fninit

    /* Load a valid 64-bit TSS so ring3->ring0 transitions (int $0x80,
     * faults via IST) can fetch RSP0/IST stacks. Without this the first
     * userspace syscall triple-faults. */
    call setup_tss64

    cli
    call kernel_main

    cli
    hlt

/* Build the 64-bit TSS descriptor in the GDT (selector 0x38), populate the
 * TSS RSP0 + IST stack pointers, and load it with ltr. */
.code64
.global setup_tss64
setup_tss64:
    /* IST1/2/3 stack tops (used by #DF/#GP/#PF/#SS/NMI gates). */
    lea ist1_stack_top(%rip), %rax
    movq %rax, tss64 + 36
    lea ist2_stack_top(%rip), %rax
    movq %rax, tss64 + 44
    lea ist3_stack_top(%rip), %rax
    movq %rax, tss64 + 52

    /* Initial RSP0 (overwritten per-task by set_tss_kernel_stack later). */
    lea stack_top(%rip), %rax
    movq %rax, tss64 + 4

    /* Point the I/O-map base at offset 104 (the bitmap defined after the TSS
     * core) so the CPU enforces per-port ring-3 I/O permission. */
    movw $104, tss64 + 102

    /* Encode the 16-byte TSS descriptor at gdt64 offset 56 (selector 0x38). The
     * limit now spans the 8192-byte I/O bitmap + terminator (tss64_end - tss64 -
     * 1 = 8296 = 0x2068), not just the 104-byte core. */
    lea gdt64_start(%rip), %rdi
    lea tss64(%rip), %rax
    movw $0x2068, 56(%rdi)     /* limit[15:0] = sizeof(TSS incl. iomap)-1 */
    movw %ax, 58(%rdi)         /* base[15:0] */
    movb $0x89, 61(%rdi)       /* access: present, type=9 (avail 64-bit TSS) */
    movb $0x00, 62(%rdi)       /* limit[19:16]=0, flags=0 */
    shrq $16, %rax
    movb %al, 60(%rdi)         /* base[23:16] */
    movb %ah, 63(%rdi)         /* base[31:24] */
    shrq $16, %rax
    movl %eax, 64(%rdi)        /* base[63:32] */
    movl $0, 68(%rdi)          /* reserved */

    movw $0x38, %ax
    ltr %ax
    ret

.section .text
.code64
.global setup_full_early_64bit_env
setup_full_early_64bit_env:

    lea ist1_stack_top(%rip), %rax
    movq %rax, tss64 + 36
    lea ist2_stack_top(%rip), %rax
    movq %rax, tss64 + 44
    lea ist3_stack_top(%rip), %rax
    movq %rax, tss64 + 52

    lea gdt64_start(%rip), %rdi
    lea tss64(%rip), %rax
    movw %ax, 24(%rdi)
    shrq $16, %rax
    movb %al, 28(%rdi)
    movb %ah, 29(%rdi)
    shrq $32, %rax
    movl %eax, 32(%rdi)
    movw $103, 26(%rdi)
    movb $0x89, 30(%rdi)
    movb $0x00, 31(%rdi)

    movw $0x18, %ax
    ltr %ax

    lea early_idt64_table(%rip), %rdi
    lea early_page_fault64(%rip), %rax
    lea early_generic_halt64(%rip), %rbx

    mov $0, %rcx
1:
    cmp $32, %rcx
    jge 2f

    movq %rbx, %rdx
    movb $1, %r8b

    cmp $14, %rcx
    jne 3f
    movq %rax, %rdx
3:
    movw %dx, 0(%rdi)
    movw $0x08, 2(%rdi)
    movb %r8b, 4(%rdi)
    movb $0x8E, 5(%rdi)
    shrq $16, %rdx
    movw %dx, 6(%rdi)
    shrq $16, %rdx
    movl %edx, 8(%rdi)
    movl $0, 12(%rdi)

    add $16, %rdi
    inc %rcx
    jmp 1b
2:
    lea early_idt64_ptr(%rip), %rax
    lidt (%rax)
    ret

.section .data
.align 16
early_idt64_table:
    .skip 32 * 16

early_idt64_ptr:
    .word (32 * 16) - 1
    .quad early_idt64_table

.global early_generic_halt64
early_generic_halt64:
    cli
    hlt
    jmp .

.section .data
.global gdt64_start
.align 16
gdt64_start:
    .quad 0x0000000000000000
    .quad 0x00209A0000000000
    .quad 0x0000920000000000
    .quad 0x0000F20000000000
    .quad 0x0020FB0000000000
    .quad 0x00CFFB000000FFFF
    .quad 0x00CFF3000000FFFF
    .quad 0x0000000000000000   /* 0x38: 64-bit TSS descriptor (low),  filled at runtime */
    .quad 0x0000000000000000   /* 0x40: 64-bit TSS descriptor (high), filled at runtime */
#ifdef SMP
    /* Per-CPU (application-processor) 64-bit TSS descriptors, filled at runtime
     * by setup_ap_tss(). Each 64-bit TSS descriptor occupies two 8-byte GDT
     * slots, so these are selectors 0x48 / 0x58 / 0x68 for CPUs 1..MAX_CPUS-1. */
    .quad 0x0000000000000000   /* 0x48: AP cpu 1 (low)  */
    .quad 0x0000000000000000   /* 0x50: AP cpu 1 (high) */
    .quad 0x0000000000000000   /* 0x58: AP cpu 2 (low)  */
    .quad 0x0000000000000000   /* 0x60: AP cpu 2 (high) */
    .quad 0x0000000000000000   /* 0x68: AP cpu 3 (low)  */
    .quad 0x0000000000000000   /* 0x70: AP cpu 3 (high) */
#endif
gdt64_end:

.global gdt64_ptr
gdt64_ptr:
    .word gdt64_end - gdt64_start - 1
    .quad gdt64_start

gdt64_ptr32:
    .word gdt64_end - gdt64_start - 1
    .long gdt64_start

.global tss64
.align 16
tss64:
    .long 0, 0                      /* 0..7:  reserved + RSP0[31:0] */
    .quad 0                         /* 8..15: RSP0[63:32], RSP1[31:0] */
    .quad 0, 0, 0                   /* 16..39 */
    .quad 0, 0, 0, 0, 0, 0, 0       /* 40..95 */
    .quad 0                         /* 96..103: includes the iomap_base word at
                                       offset 102, set to 104 at runtime by
                                       setup_tss64 so the CPU consults the bitmap
                                       below for ring-3 I/O-port access. */
/* Per-task I/O permission bitmap (offset 104): one bit per x86 I/O port, set = the
 * port is DENIED to ring 3. Default all-deny (0xFF); set_tss_kernel_stack / the
 * driver framework clear bits for a task's granted CAP_IO_PORT windows. The final
 * 0xFF byte is the Intel-recommended terminator. Extends the TSS to 8297 bytes;
 * the descriptor limit in setup_tss64 is widened to match. */
.global tss64_iomap
tss64_iomap:
    .fill 8192, 1, 0xFF
    .byte 0xFF
tss64_end:

.align 16
ist1_stack_bottom:
    .space 4096
ist1_stack_top:

.align 16
ist2_stack_bottom:
    .space 4096
ist2_stack_top:

.align 16
ist3_stack_bottom:
    .space 4096
ist3_stack_top:

.section .bss
.align 16
stack_bottom:
    .space 16384
.global stack_top
stack_top:

    .align 16
early_handler_stack_bottom:
    .space 4096
.global early_handler_stack_top
early_handler_stack_top:

.align 4096
.global pml4
pml4:
    .space 4096
pdpt:
    .space 4096
pd:
    .space 4096

.align 4096
high_pdpt:
    .space 4096

.section .rodata
#ifdef SMP
/* Real-mode AP startup trampoline (src/boot/ap_trampoline.S), linked flat at
 * 0x8000 and copied there by smp_start_aps before the broadcast SIPI. Only
 * embedded in the SMP build. */
.align 16
.global ap_trampoline_start
ap_trampoline_start:
.incbin "src/boot/ap_trampoline.bin"
.global ap_trampoline_end
ap_trampoline_end:
#endif

.align 16
.global embedded_shell_bin_start
embedded_shell_bin_start:
.incbin "userspace/shell.bin"
.global embedded_shell_bin_end
embedded_shell_bin_end:

/* init: the ring-3 PID-1 process the kernel launches first; it spawns and
 * supervises the shell. Always embedded (it is the boot userspace entry). */
.align 16
.global embedded_init_bin_start
embedded_init_bin_start:
.incbin "userspace/init.bin"
.global embedded_init_bin_end
embedded_init_bin_end:

/* hello and captest are always embedded so 'spawn hello'/'spawn captest' work
 * without a serial-port upload. */
.align 16
.global embedded_hello_bin_start
embedded_hello_bin_start:
.incbin "userspace/hello.bin"
.global embedded_hello_bin_end
embedded_hello_bin_end:

.align 16
.global embedded_captest_bin_start
embedded_captest_bin_start:
.incbin "userspace/captest.bin"
.global embedded_captest_bin_end
embedded_captest_bin_end:

/* fs_server is also always embedded.  The FS_SELFTEST build embeds it under the
 * same symbol names in the block below; this guard prevents duplicate definitions. */
#ifndef FS_SELFTEST
.align 16
.global embedded_fsserver_bin_start
embedded_fsserver_bin_start:
.incbin "userspace/fs_server.bin"
.global embedded_fsserver_bin_end
embedded_fsserver_bin_end:
#endif

#if defined(INIT_DISK_SELFTEST) || defined(STORAGE_RING3_DISK)
/* disk_server: the ring-3 ATA driver, spawned by name from init. Embedded either
 * for the INIT_DISK_SELFTEST proof or for the STORAGE_RING3_DISK block-service role
 * (the real fs disk). */
.align 16
.global embedded_diskserver_bin_start
embedded_diskserver_bin_start:
.incbin "userspace/disk_server.bin"
.global embedded_diskserver_bin_end
embedded_diskserver_bin_end:
#endif

#ifdef ELF_SELFTEST
/* Real multi-segment ELF used by the in-kernel ELF-loader self-test
 * (elf_loader_selftest). Only embedded in the ELF_SELFTEST build. */
.align 16
.global embedded_elftest_start
embedded_elftest_start:
.incbin "userspace/elftest.elf"
.global embedded_elftest_end
embedded_elftest_end:
#endif

#if defined(PREEMPT_SELFTEST) || defined(SMP_SELFTEST) || defined(PROC_SELFTEST)
/* Flat userspace tracer used by the preemptive-scheduling self-test
 * (preempt_selftest), reused as the worker payload by the SMP self-test
 * (smp_selftest) and as the "looper" kill target by the process-control
 * self-test (proc_selftest). Only embedded in those gated builds. */
.align 16
.global embedded_preempttest_bin_start
embedded_preempttest_bin_start:
.incbin "userspace/preempttest.bin"
.global embedded_preempttest_bin_end
embedded_preempttest_bin_end:
#endif

#ifdef PROC_SELFTEST
/* Flat userspace driver for the process-control self-test (proc_selftest):
 * spawns children and exercises SYS_EXIT / SYS_KILL. Only in PROC_SELFTEST. */
.align 16
.global embedded_proctest_bin_start
embedded_proctest_bin_start:
.incbin "userspace/proctest.bin"
.global embedded_proctest_bin_end
embedded_proctest_bin_end:

/* exectest: a child the proctest driver spawns to exercise SYS_EXEC_NAMED — it
 * execs itself into "hello" in place. Only in PROC_SELFTEST. */
.align 16
.global embedded_exectest_bin_start
embedded_exectest_bin_start:
.incbin "userspace/exectest.bin"
.global embedded_exectest_bin_end
embedded_exectest_bin_end:

/* grantee: a child the proctest driver spawns to exercise SYS_CAP_GRANT — it
 * uses a delegated CAP_AUDIT and checks that unauthorised grants fail. Only in
 * PROC_SELFTEST. */
.align 16
.global embedded_grantee_bin_start
embedded_grantee_bin_start:
.incbin "userspace/grantee.bin"
.global embedded_grantee_bin_end
embedded_grantee_bin_end:

/* sigtarget: a child the proctest driver signals to exercise SYS_SIGNAL — it
 * registers a handler that fires on delivery. Only in PROC_SELFTEST. */
.align 16
.global embedded_sigtarget_bin_start
embedded_sigtarget_bin_start:
.incbin "userspace/sigtarget.bin"
.global embedded_sigtarget_bin_end
embedded_sigtarget_bin_end:

/* faulter: a child that takes an unhandled #UD fault, to exercise the fault-kill
 * wake path (SYS_WAIT waiter woken on a *fault* death). Only in PROC_SELFTEST. */
.align 16
.global embedded_faulter_bin_start
embedded_faulter_bin_start:
.incbin "userspace/faulter.bin"
.global embedded_faulter_bin_end
embedded_faulter_bin_end:

/* sigwaiter: blocks in SYS_WAIT on an immortal target, to exercise async signal
 * delivery interrupting a blocked wait. Only in PROC_SELFTEST. */
.align 16
.global embedded_sigwaiter_bin_start
embedded_sigwaiter_bin_start:
.incbin "userspace/sigwaiter.bin"
.global embedded_sigwaiter_bin_end
embedded_sigwaiter_bin_end:

/* argtest: spawned with a known argument vector to exercise full argv passing;
 * reads its args back and checks them. Only in PROC_SELFTEST. */
.align 16
.global embedded_argtest_bin_start
embedded_argtest_bin_start:
.incbin "userspace/argtest.bin"
.global embedded_argtest_bin_end
embedded_argtest_bin_end:
#endif

#ifdef SIGNAL_SELFTEST
/* Flat userspace payload for the signal-handling self-test (signal_selftest):
 * registers a fault handler, then faults on purpose. Only in SIGNAL_SELFTEST. */
.align 16
.global embedded_sigtest_bin_start
embedded_sigtest_bin_start:
.incbin "userspace/sigtest.bin"
.global embedded_sigtest_bin_end
embedded_sigtest_bin_end:
#endif

#ifdef NEWLIB_SELFTEST
/* PIE hello_newlib binary: newlib printf/malloc/string smoke test. */
.align 16
.global embedded_hello_newlib_bin_start
embedded_hello_newlib_bin_start:
.incbin "userspace/hello_newlib.bin"
.global embedded_hello_newlib_bin_end
embedded_hello_newlib_bin_end:
#endif

#ifdef NOTIFY_SELFTEST
/* PIE notifytest binary: spawned twice (waiter + sender) to exercise the
 * async SYS_NOTIFY / SYS_WAIT_NOTIFY badge round-trip. */
.align 16
.global embedded_notifytest_bin_start
embedded_notifytest_bin_start:
.incbin "userspace/notifytest.bin"
.global embedded_notifytest_bin_end
embedded_notifytest_bin_end:
#endif

#ifdef FS_SELFTEST
/* PIE userspace fs_server + a client that drives it over IPC, used by the
 * filesystem self-test (fs_selftest). Only embedded in the FS_SELFTEST build. */
.align 16
.global embedded_fsserver_bin_start
embedded_fsserver_bin_start:
.incbin "userspace/fs_server.bin"
.global embedded_fsserver_bin_end
embedded_fsserver_bin_end:
.align 16
.global embedded_fsclient_bin_start
embedded_fsclient_bin_start:
.incbin "userspace/fsclient.bin"
.global embedded_fsclient_bin_end
embedded_fsclient_bin_end:
#endif

#if defined(INIT_FS_SELFTEST) && !defined(FS_SELFTEST)
/* fsclient for the init-delegated FS integration test (INIT_FS_SELFTEST). The
 * fs_server is already embedded above (the #ifndef FS_SELFTEST block); only the
 * client needs adding here. */
.align 16
.global embedded_fsclient_bin_start
embedded_fsclient_bin_start:
.incbin "userspace/fsclient.bin"
.global embedded_fsclient_bin_end
embedded_fsclient_bin_end:
#endif