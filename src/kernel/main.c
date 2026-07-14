


#include "kernel.h"

extern uint32_t kernel_page_directory[];
extern tcb_t tasks[MAX_TASKS];
extern int current_task;
extern void set_tss_kernel_stack(uintptr_t);
extern uint8_t gdt64_start[];
extern uint8_t tss64[];

#ifdef DEBUG_SHELL
void __attribute__((noreturn)) shell_prompt_loop(void) {
    print("> ");
    while (1) {
        char cmd[128];
        int len = 0;

        while (len < 127) {
            char ch = console_getc();

            if (ch == '\r' || ch == '\n') {
                print("\n");
                break;
            }
            if (ch == '\b' || ch == 0x7F) {
                if (len > 0) { len--; print("\b \b"); }
                continue;
            }
            if (ch < 32 || ch > 126) continue;

            print_char(ch);
            cmd[len++] = ch;
        }
        cmd[len] = 0;

        if (cmd[0] != 0) {
            process_user_command(cmd);
        }
        print("> ");
    }
}
#endif

void __attribute__((noreturn)) resume_shell_after_fault(void) {
#ifdef DEBUG_SHELL
    set_current_task(0);  
    set_tss_kernel_stack(tasks[0].kernel_stack_top);
    shell_prompt_loop();
#else
    /* Task teardown (and waiter wake) already happened on the fault path.
     * Park this CPU; there is no cooperative schedule() path any more. */
    kernel_idle();
#endif
}

void kernel_main(uint32_t mb_info) {
    (void)mb_info;

    asm volatile(
        "xor %%rax,%%rax\n mov %%rax,%%dr0\n mov %%rax,%%dr1\n mov %%rax,%%dr2\n"
        "mov %%rax,%%dr3\n mov %%rax,%%dr6\n mov %%rax,%%dr7\n"
        "pushfq\n andq $~0x100,(%%rsp)\n popfq\n" ::: "rax","memory");

    terminal_init();

#ifdef VBOOT_SELFTEST
    /* Runtime boot-integrity gate: verify the signed manifest against the
     * embedded Ed25519 anchor before proceeding. Noreturn — prints its marker
     * and halts (a real reject must not continue). See verified_boot.c. */
    verified_boot_selftest();
#endif

    idt_init64();
    pic_init();
    paging_init();
    cap_init();
    cpu_detect_features();
    cpu_enable_protections();   /* SMEP/SMAP — must follow feature detection */
    entropy_init();
#ifndef MINIMAL_SECURE
    ramfs_init();   /* -> storage_init(): probes for an ATA disk (persistent) and
                     * falls back to the ephemeral RAM vdisk when none is present */
#endif
    scheduler_init();
    smp_bringup();
    __asm__ volatile ("sti" ::: "memory");
    aslr_init_seed();
    set_current_task(0);
    /* Note: the 64-bit boot reaches userspace via smp_bringup() above, which
     * spawns the shell and never returns; the ELF_SELFTEST hook lives there.
     * This branch is the fallback path. */
#ifdef DEBUG_SHELL
    shell_prompt_loop();
#else
    /* Normal boot never reaches here: smp_bringup() already dropped into
     * ring 3 via sched_enter_user. This is only the fallback if that path
     * returned (e.g. embed missing). Idle — do not cooperative-schedule. */
    spawn_initial_userspace_init();
    kernel_idle();
#endif
}
