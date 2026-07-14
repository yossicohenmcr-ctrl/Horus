/* kspawn.c -- process creation: spawn-argument staging + argv marshalling,
 * do_spawn() (build address space, load staged image, endow caps), exec-in-
 * place (SYS_EXEC_NAMED), and the spawn/argv syscall handlers. Split out of
 * syscall.c. */
#include "syscall_internal.h"

#define SPAWN_MAX_ARGS   16
#define SPAWN_ARGS_BYTES 512
static uint32_t g_args_argc = 0;
static uint32_t g_args_total = 0;              /* bytes used in g_args_strbuf */
static char     g_args_strbuf[SPAWN_ARGS_BYTES];
static uint16_t g_args_len[SPAWN_MAX_ARGS];    /* length incl NUL of each arg */

/* Copy a NUL-terminated string from user vaddr `usrc` into `dst` (cap bytes incl
 * NUL). Returns length excluding NUL, or -1 on fault / no NUL within cap. */
static int copy_user_cstr(char *dst, uint32_t usrc, uint32_t cap) {
    for (uint32_t i = 0; i < cap; i++) {
        char c;
        if (copy_from_user(&c, (const void *)(addr_t)(usrc + i), 1) != 0) return -1;
        dst[i] = c;
        if (c == 0) return (int)i;
    }
    return -1;   /* over-long / no terminator within cap */
}

/* Stage the spawner's argv (argc strings at user array `uargv`) for the next
 * spawn. Clears the staging on any error so a partial vector is never applied. */
static void stage_spawn_args(uint32_t uargv, uint32_t uargc) {
    g_args_argc = 0; g_args_total = 0;
    if (uargc == 0 || uargv == 0 || uargc > SPAWN_MAX_ARGS) return;
    uint32_t ptrs[SPAWN_MAX_ARGS];
    if (copy_from_user(ptrs, (const void *)(addr_t)uargv, uargc * 4) != 0) return;
    uint32_t total = 0;
    for (uint32_t i = 0; i < uargc; i++) {
        if (total >= SPAWN_ARGS_BYTES) return;
        int len = copy_user_cstr(g_args_strbuf + total, ptrs[i], SPAWN_ARGS_BYTES - total);
        if (len < 0) return;                 /* fault or over-long: abort, no args */
        g_args_len[i] = (uint16_t)(len + 1);
        total += (uint32_t)len + 1;
    }
    g_args_argc  = uargc;
    g_args_total = total;
}

/* Marshal the staged argv onto child `tid`'s initial stack and record argc + the
 * argv[] base on its TCB. Must run with `tid` current (so copy_to_user targets
 * its address space) and before sched_prepare_user_context reads esp. Consumes
 * the staging. No-op when nothing is staged. */
static void build_child_argv(int tid) {
    if (g_args_argc == 0) return;
    uint32_t argc = g_args_argc;
    uint32_t sp   = (tasks[tid].esp ? tasks[tid].esp : 0x007ff000u) & ~0xFu;
    uint32_t str_vaddr[SPAWN_MAX_ARGS];
    uint32_t off = 0;
    for (uint32_t i = 0; i < argc; i++) {
        uint32_t len = g_args_len[i];
        sp -= len;
        copy_to_user((void *)(addr_t)sp, g_args_strbuf + off, len);
        str_vaddr[i] = sp;
        off += len;
    }
    sp &= ~3u;
    sp -= (argc + 1) * 4;                     /* argv[] array, NULL-terminated */
    uint32_t argv_base = sp;
    for (uint32_t i = 0; i < argc; i++)
        copy_to_user((void *)(addr_t)(argv_base + i * 4), &str_vaddr[i], 4);
    uint32_t nullp = 0;
    copy_to_user((void *)(addr_t)(argv_base + argc * 4), &nullp, 4);
    tasks[tid].argc     = argc;
    tasks[tid].argv_ptr = argv_base;
    tasks[tid].esp      = (argv_base - 16) & ~0xFu;
    g_args_argc = 0; g_args_total = 0;
}

static int do_spawn_inner(void) {
    if (!program_armed) {
        return -1;
    }

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) {
        return -2;
    }

    uint32_t load_base = USER_AREA_BASE;
    uint32_t stack_top = 0;
    choose_image_placement(new_id, &load_base, &stack_top);

    create_task(new_id, load_base + armed_hdr.entry, stack_top, load_base);

    load_staged_image_into(new_id, load_base);

    /* load_staged_image_into left `new_id` current, so copy_to_user targets its
     * address space: marshal any staged argv onto its stack before its initial
     * context is fabricated (this lowers new_id's esp below the argv block). */
    build_child_argv(new_id);

    uint32_t cap6_serial = 0;
    struct capability *creator_admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (creator_admin && creator_admin->type == CAP_USER) {
        cap6_serial = cap_alloc_fresh_serial();
    }
    spin_lock(&cap_lock);
    if (creator_admin && creator_admin->type == CAP_USER) {
        tasks[new_id].cspace[6].type   = CAP_USER;
        tasks[new_id].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[new_id].cspace[6].object = 0;
        /* Lineage link, so revoking the creator's admin cap revokes this one too.
         * The semantic admin marker now lives in `badge`, separate from the link,
         * so it can never be mistaken for a serial during a revocation sweep (I2). */
        tasks[new_id].cspace[6].badge  = 0xC0DE0006U;
        tasks[new_id].cspace[6].parent = creator_admin->serial;  /* 0 if the creator has none */
        tasks[new_id].cspace[6].serial = cap6_serial;
        tasks[new_id].cspace[6].generation = creator_admin->generation;
    }
    spin_unlock(&cap_lock);

    /* Fabricate an initial resumable trap frame so sched_enter_user and the
     * preemptive scheduler can iretq into this task (entry/esp/cr3 are final). */
    sched_prepare_user_context(new_id, tasks[new_id].eip,
                               tasks[new_id].esp ? tasks[new_id].esp : 0x007ff000ULL);

    return new_id;
}

/* Give `spawner` a CAP_TCB capability to child `pid`, so it can wait on, signal,
 * or terminate the child (SYS_WAIT / SYS_KILL). Installed in the first free
 * cspace slot at or above 16, clear of the reserved low slots, with a fresh
 * serial so cap_lookup accepts it. No-op for the kernel/idle spawner. */
static void grant_child_tcb_cap(int spawner, int pid) {
    if (spawner <= 0 || spawner >= MAX_TASKS || pid <= 0 || pid >= MAX_TASKS) return;
    capability_t *cs = tasks[spawner].cspace;
    if (!cs) return;
    for (uint32_t s = 16; s < tasks[spawner].cspace_size; s++) {
        if (cs[s].type == CAP_NULL) {
            cs[s].type       = CAP_TCB;
            cs[s].rights     = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
            cs[s].object     = (uint64_t)pid;
            cs[s].badge      = 0;
            cs[s].serial     = cap_alloc_fresh_serial();
            cs[s].generation = 0;
            cs[s].parent     = 0;   /* kernel-granted TCB cap: no derivation parent */
            break;
        }
    }
}

/* do_spawn must run in the kernel address space: create_user_pagedir and the
 * image loader reach freshly-allocated physical pages through the kernel's low
 * identity map, which a ring-3 caller's CR3 does not provide, and do_spawn_inner
 * installs the child as the current task. This wrapper switches to the kernel
 * page tables for the duration and restores the caller's address space + current
 * task on return, so SYS_SPAWN works from ring 3 and the caller continues. The
 * caller is also granted a CAP_TCB to the new child. */
int do_spawn(void) {
    extern uint64_t pml4[];
    uint64_t caller_cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(caller_cr3));
    int caller_task = get_current_task();
    uint64_t kcr3 = (uint64_t)(uintptr_t)pml4;

    if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    int pid = do_spawn_inner();
    set_current_task(caller_task);
    if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(caller_cr3) : "memory");

    if (pid > 0) grant_child_tcb_cap(caller_task, pid);
    /* A child runs as its spawner's identity. This is what lets init's uid-0
     * fs_server pass the object-store's uid==0 gate, and it closes a latent
     * privilege bug: previously a child kept its (BSS-zero) task-slot uid, so a
     * task spawned by a non-root user could come up as uid 0. Authority still
     * flows through capabilities; uid only mirrors the spawner. */
    if (pid > 0) {
        tasks[pid].uid = tasks[caller_task].uid;
        tasks[pid].gid = tasks[caller_task].gid;
    }
    return pid;
}

/* Set by h_exec_named to ask interrupt_handler64 to re-enter this task via the
 * fresh context sched_prepare_user_context fabricated for it, instead of iretq'ing
 * back into the (now-replaced) old image. -1 when no exec re-entry is pending. */
int g_exec_reenter_task = -1;

/* SYS_EXEC_NAMED (64): replace the calling task's image with a named embedded
 * binary, keeping the same task id and cspace (capabilities survive the exec,
 * POSIX-style). Like do_spawn the rebuild+load must run in the kernel address
 * space (create_user_pagedir and the loader reach fresh physical pages through
 * the kernel identity map); unlike do_spawn we do NOT restore the caller — on
 * success we switch to the freshly-built image's CR3 and drop to ring 3 at its
 * entry, so this never returns. The old page directory/frames leak, consistent
 * with the kernel's non-freeing task teardown (task_teardown only marks slots
 * dead). Capability (slot 3, WRITE|EXEC) is enforced centrally by the table. */
/* Shared tail of SYS_EXEC_NAMED / SYS_EXEC_IMAGE: replace the current task's
 * image in place with the currently-armed staged image, keeping its task id and
 * cspace (capabilities survive the exec, POSIX-style). Preconditions: a program
 * is armed (arm_named_binary / arm_image_from_user succeeded) and any new argv is
 * already staged from the caller's still-live address space. Like do_spawn the
 * rebuild+load runs in the kernel address space; unlike do_spawn we do NOT
 * restore the caller — on success we hand interrupt_handler64 a fresh ring-3
 * context (g_exec_reenter_task) for the new image, so this never returns. The old
 * page directory/frames leak, consistent with the kernel's non-freeing teardown. */
static void exec_into_armed_image(struct regs *r) {
    int cur = get_current_task();

    /* Past this point the caller's image is torn down and replaced; there is no
     * clean return path. Switch to the kernel address space for the rebuild. */
    extern uint64_t pml4[];
    uint64_t kcr3 = (uint64_t)(uintptr_t)pml4;
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");

    uint32_t load_base = USER_AREA_BASE;
    uint32_t stack_top = 0;
    choose_image_placement(cur, &load_base, &stack_top);

    /* Rebuild only the address space (fresh PML4 into tasks[cur].cr3); the cspace
     * is untouched so capabilities survive. Reset signal dispositions like a real
     * exec. create_user_pagedir reads image_base for the premap, so set it first. */
    tasks[cur].image_base  = load_base;
    tasks[cur].image_end   = load_base;
    tasks[cur].esp         = stack_top ? (stack_top - 256) : 0;
    tasks[cur].sig_handler  = 0;
    tasks[cur].in_signal    = 0;
    tasks[cur].pending_sigs = 0;
    tasks[cur].sig_mask     = 0;
    tasks[cur].sig_altstack_sp   = 0;   /* a fresh image has no alternate signal stack */
    tasks[cur].sig_altstack_size = 0;
    tasks[cur].sig_on_stack      = 0;
    tasks[cur].spawn_arg    = 0;
    tasks[cur].argc         = 0;
    tasks[cur].argv_ptr     = 0;
    create_user_pagedir(cur);

    load_staged_image_into(cur, load_base);   /* sets eip/heap/name, disarms */

    /* Marshal any staged argv onto the freshly-built stack (load_staged_image_into
     * left `cur` current, so copy_to_user targets its new address space); this
     * lowers tasks[cur].esp below the argv block before the frame is fabricated. */
    build_child_argv(cur);

    /* Enter the new image the same way spawn / the timer / the exit-switch enter
     * a task: fabricate a fresh ring-3 trap frame (IF set, zeroed GP regs, ring-3
     * selectors) and hand it to the ISR epilogue via saved_ksp. A hand-rolled
     * lretq from inside the syscall ISR runs with interrupts off and the wrong
     * initial context; this reuses the proven resume path instead. interrupt_
     * handler64 sees g_exec_reenter_task and switches CR3 + kernel stack + resumes
     * the fabricated frame. Runs with the kernel CR3 still active; the switch to
     * tasks[cur].cr3 happens in exec_reenter_switch before the iretq. */
    uint64_t new_eip = tasks[cur].eip;
    uint64_t new_esp = tasks[cur].esp ? (uint64_t)tasks[cur].esp : 0x007ff000ULL;
    sched_prepare_user_context(cur, new_eip, new_esp);
    g_exec_reenter_task = cur;
    r->eax = 0;
}

/* SYS_EXEC_NAMED (64): replace the caller's image with a named embedded binary.
 * Resolve+arm the name and stage argv while the caller's address space is still
 * live (a bad name fails cleanly, image intact), then hand off to the shared
 * exec tail. Capability (slot 3, WRITE|EXEC) is enforced centrally by the table. */
void h_exec_named(struct regs *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->eax = (uint32_t)SYS_ERR_PERM; return; }

    if (!r->ebx) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    char name[32];
    uint32_t len = r->ecx ? r->ecx : 31u;
    if (len > 31) len = 31;
    if (copy_from_user(name, (void *)(addr_t)r->ebx, len) != 0) {
        r->eax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    name[len] = 0;
    if (arm_named_binary(name) != 0) { r->eax = (uint32_t)SYS_ERR_NOENT; return; }

    /* Stage the new argv (esi = user char* array, edi = argc) NOW, while the
     * caller's old address space is still active so copy_from_user can read the
     * strings; it is marshalled onto the fresh stack after the rebuild. */
    stage_spawn_args(r->esi, r->edi);

    exec_into_armed_image(r);   /* no clean return on success */
}

/* SYS_EXEC_IMAGE (71): replace the caller's image with a program image the caller
 * supplies in its own memory (execve-from-fd — the caller read it from a file via
 * the fs_server). Validate+arm the image and stage argv while the caller's
 * address space is still live (a bad image fails cleanly, image intact), then
 * hand off to the shared exec tail. ebx=image, ecx=len, esi=argv, edi=argc.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the table. */
void h_exec_image(struct regs *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->eax = (uint32_t)SYS_ERR_PERM; return; }

    int rc = arm_image_from_user(r->ebx, r->ecx, 0);
    if (rc != 0) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }   /* image intact on failure */

    /* Stage argv while the caller's old address space is still active. */
    stage_spawn_args(r->esi, r->edi);

    exec_into_armed_image(r);   /* no clean return on success */
}

/* SYS_SPAWN_IMAGE (70): spawn a child from a program image the caller supplies in
 * its own memory (execve-from-fd, spawn form). Mirrors h_spawn but arms the
 * loader from the caller's buffer instead of a named embedded binary.
 * ebx=image, ecx=len, edx=one-word spawn arg, esi=argv, edi=argc. Returns the
 * child pid, or a negative SYS_ERR_*. Slot-3 WRITE|EXEC enforced by the table. */
void h_spawn_image(struct regs *r) {
    int rc = arm_image_from_user(r->ebx, r->ecx, 0);
    if (rc != 0) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }

    /* Stage the caller's argv before the child exists; do_spawn_inner marshals it
     * onto the child's stack. Read here while the caller is still current. */
    stage_spawn_args(r->esi, r->edi);
    int pid = do_spawn();       /* consumes the armed image */
    g_args_argc = 0;            /* drop staging if the spawn failed before consuming it */
    if (pid > 0 && pid < MAX_TASKS) tasks[pid].spawn_arg = r->edx;
    r->eax = (uint32_t)pid;
}


void h_spawn(struct regs *r) {
    if (r->ebx) {
        char name[32];
        uint32_t len = r->ecx ? r->ecx : 31u;
        if (len > 31) len = 31;
        if (copy_from_user(name, (void *)(addr_t)r->ebx, len) != 0) {
            r->eax = (uint32_t)SYS_ERR_FAULT;
            return;
        }
        name[len] = 0;
        int rc = arm_named_binary(name);
        if (rc != 0) {
            r->eax = (uint32_t)SYS_ERR_NOENT;
            return;
        }
    }
    /* Stage the caller's argv (esi = user char* array, edi = argc) before the
     * child exists; do_spawn_inner marshals it onto the child's stack. Read here
     * while the caller is still current so copy_from_user hits its memory. */
    stage_spawn_args(r->esi, r->edi);
    int pid = do_spawn();
    g_args_argc = 0;   /* drop staging if the spawn failed before consuming it */
    /* Hand the child its one-word spawn argument (edx), retrievable via
     * SYS_SPAWN_ARG. Zero for callers that don't pass one. */
    if (pid > 0 && pid < MAX_TASKS) tasks[pid].spawn_arg = r->edx;
    /* Don't switch to the child here: do_spawn returns with the caller restored
     * as the current task, and the child (runnable) is picked up by the timer.
     * The old cooperative schedule() mis-handles a ring-3 caller mid-syscall. */
    r->eax = (uint32_t)pid;
}

/* SYS_SPAWN_ARG (68): return the one-word argument this task was spawned with. */
void h_spawn_arg(struct regs *r) {
    r->eax = tasks[get_current_task()].spawn_arg;
}

/* SYS_GET_ARGV (69): return this task's argc and write the argv[] base (a user
 * vaddr into its own stack) to *ebx. argc 0 / argv 0 when spawned without args. */
void h_get_argv(struct regs *r) {
    int cur = get_current_task();
    uint32_t argv_ptr = tasks[cur].argv_ptr;
    if (r->ebx) copy_to_user((void *)(addr_t)r->ebx, &argv_ptr, 4);
    r->eax = tasks[cur].argc;
}

/* SYS_GETUID (29). */

