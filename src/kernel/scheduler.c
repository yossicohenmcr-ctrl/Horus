#include "kernel.h"

tcb_t tasks[MAX_TASKS];
int current_task = 0;
int percpu_current_task[MAX_CPUS];

#ifdef SMP
/* Which CPU is currently running each task (-1 == not running anywhere). The SMP
 * scheduler's mutual-exclusion guard: preempt_on_tick only ever claims a task
 * whose entry is -1, so a task's single kernel stack + saved trap frame are
 * never touched by two CPUs at once. Managed under the scheduler lock. */
int task_running_cpu[MAX_TASKS];

/* Bitmask of CPUs that have run at least one user task (bit c == CPU c). The SMP
 * self-test reads it to confirm work actually landed on more than one core. */
volatile unsigned smp_cpus_ran_tasks = 0;
#endif

static uint8_t kernel_stacks[MAX_TASKS][KERNEL_STACK_SIZE] __attribute__((aligned(16)));

spinlock_t scheduler_lock;
spinlock_t page_lock;
spinlock_t cap_lock;
spinlock_t endpoint_lock;
spinlock_t storage_lock;

addr_t current_kernel_stack_top = 0;  

void scheduler_lock_acquire(void);
void scheduler_lock_release(void);

struct endpoint endpoints[MAX_ENDPOINTS];

uint32_t system_ticks = 0;

void scheduler_init(void) {
    for (int i = 0; i < MAX_TASKS; i++) {
        tasks[i].state = 0;
        tasks[i].esp = 0;
        tasks[i].eip = 0;
        tasks[i].cap_tcb = 0;
        tasks[i].cr3 = 0;
        tasks[i].priority = 1;
        tasks[i].cspace = 0;
        tasks[i].cspace_size = 0;
        tasks[i].heap_start = 0;
        tasks[i].heap_current = 0;
        tasks[i].heap_end = 0;
        tasks[i].name[0] = 0;
        tasks[i].waiter = -1;
        tasks[i].blocked_on = -1;
        tasks[i].ipc_role = 0;
        tasks[i].in_kernel = 0;
        tasks[i].blocked_on_notif = -1;
        tasks[i].pending_block = 0;
        tasks[i].auth_fail_count = 0;
        tasks[i].auth_lockout_until = 0;
    }

    create_task(0, 0, 0, 0);

    tasks[0].uid = 0;
    tasks[0].gid = 0;

    users_init();

    for (int i = 0; i < MAX_ENDPOINTS; i++) {
        endpoints[i].has_message = 0;
        endpoints[i].msg_len = 0;
        endpoints[i].sender_task = -1;
        endpoints[i].last_sender = -1;
    }

    
    for (int c = 0; c < MAX_CPUS; c++) percpu_current_task[c] = 0;
    percpu_current_task[0] = 0;
    current_task = 0;
    scheduler_lock = (spinlock_t){0};
    page_lock = (spinlock_t){0};
    cap_lock = (spinlock_t){0};
    endpoint_lock = (spinlock_t){0};
    storage_lock = (spinlock_t){0};

    current_kernel_stack_top = KERNEL_TSS_STACK;
}

void create_task(int id, addr_t entry, addr_t stack_top, addr_t image_base) {
    if (id >= MAX_TASKS) return;

    /* Record the (possibly ASLR-randomized) image base before create_user_pagedir
     * runs, so it premaps the image window at the right virtual address. Default
     * to the fixed low base for task 0 / callers that don't relocate. */
    tasks[id].image_base = image_base ? (uint32_t)image_base : (uint32_t)USER_AREA_BASE;
    tasks[id].image_end  = tasks[id].image_base;   /* refined by the loader once the image size is known */

    tasks[id].state = 1;
    tasks[id].esp = (addr_t)(stack_top ? (stack_top - 256) : 0);
    tasks[id].eip = entry;
    tasks[id].cap_tcb = id;

    /* Each task owns a distinct kernel stack (shared kernel mapping, present in
     * every address space). Pin it now so the TSS RSP0 and the preemptive
     * scheduler's saved/fabricated trap frame agree on one address. */
    tasks[id].kernel_stack_top = (uint64_t)&kernel_stacks[id][KERNEL_STACK_SIZE - 16];
    tasks[id].saved_ksp = 0;
    tasks[id].runnable_ctx = 0;
    tasks[id].pending_block = 0;
    tasks[id].sig_handler = 0;   /* no signal handler until the task registers one */
    tasks[id].in_signal = 0;
    tasks[id].pending_sigs = 0;   /* no async signals queued */
    tasks[id].sig_mask     = 0;   /* nothing blocked */
    tasks[id].sig_altstack_sp   = 0;   /* no alternate signal stack until registered */
    tasks[id].sig_altstack_size = 0;
    tasks[id].sig_on_stack      = 0;
    tasks[id].spawn_arg    = 0;   /* no spawn argument */
    tasks[id].argc         = 0;   /* no argument vector */
    tasks[id].argv_ptr     = 0;

create_user_pagedir(id);

    static struct capability cspace_pool[MAX_TASKS][256];
    tasks[id].cspace = cspace_pool[id];
    tasks[id].cspace_size = 256;

    /* Zero the entire cspace before installing initial capabilities.
     * cspace_pool is static (zeroed at BSS init) but task slots are reused:
     * a dead task's CAP_USER/CAP_CONSOLE/etc. would otherwise survive into
     * the next task spawned at the same index, granting it unearned authority. */
    for (int s = 0; s < 256; s++) {
        tasks[id].cspace[s].type       = CAP_NULL;
        tasks[id].cspace[s].rights     = 0;
        tasks[id].cspace[s].object     = 0;
        tasks[id].cspace[s].badge      = 0;
        tasks[id].cspace[s].serial     = 0;
        tasks[id].cspace[s].generation = 0;
        tasks[id].cspace[s].parent     = 0;   /* clear the lineage link too, or a
                                               * reused slot inherits a dead task's
                                               * derivation parent (I2). */
    }

    /* Reset the I/O-port cache: a reused slot must not inherit a dead driver's
     * granted ports. With no CAP_IO_PORT caps, this task runs all-ports-denied
     * until one is explicitly granted (which calls cap_cache_io_ports). */
    tasks[id].io_range_n  = 0;
    tasks[id].has_io_caps = 0;

    tasks[id].cspace[0].type   = CAP_TCB;
    tasks[id].cspace[0].rights = CAP_RIGHT_ALL;
    tasks[id].cspace[0].object = id;
    tasks[id].cspace[0].badge  = 0;
    tasks[id].cspace[0].serial = (0xB0000000U | ((uint32_t)id << 16) | 0U);
    tasks[id].cspace[0].generation = 0;

    tasks[id].cspace[3].type   = CAP_FRAME;
    tasks[id].cspace[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    tasks[id].cspace[3].object = USER_AREA_BASE;
    tasks[id].cspace[3].badge  = 0;
    tasks[id].cspace[3].serial = (0xB0000000U | ((uint32_t)id << 16) | 3U);
    tasks[id].cspace[3].generation = 0;

    tasks[id].cspace[4].type   = CAP_ENDPOINT;
    tasks[id].cspace[4].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    tasks[id].cspace[4].object = 0;
    tasks[id].cspace[4].badge  = 0;
    tasks[id].cspace[4].serial = (0xB0000000U | ((uint32_t)id << 16) | 4U);
    tasks[id].cspace[4].generation = 0;

    tasks[id].cspace[5].type   = CAP_ENDPOINT;
    tasks[id].cspace[5].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    tasks[id].cspace[5].object = 1;
    tasks[id].cspace[5].badge  = 0;
    tasks[id].cspace[5].serial = (0xB0000000U | ((uint32_t)id << 16) | 5U);
    tasks[id].cspace[5].generation = 0;

    
    if (id == 0) {
        tasks[id].cspace[8].type   = CAP_CONSOLE;
        tasks[id].cspace[8].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[8].object = 0;
        tasks[id].cspace[8].badge  = 0;
        tasks[id].cspace[8].serial = 0xC0DE0008U;
        tasks[id].cspace[8].generation = 0;

        tasks[id].cspace[9].type   = CAP_ENCRYPTED_STORAGE;
        tasks[id].cspace[9].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[9].object = 0;
        tasks[id].cspace[9].badge  = 0;
        tasks[id].cspace[9].serial = 0xC0DE0009U;
        tasks[id].cspace[9].generation = 0;
    }
}

void create_user_task(int id, addr_t entry, addr_t stack_top) {
    create_task(id, entry, stack_top, USER_AREA_BASE);
}


void timer_handler(void) {
    system_ticks++;
}

uint32_t get_system_ticks(void) {
    return system_ticks;
}

/* ----------------------------------------------------------------------------
 * Preemptive scheduling
 *
 * The timer ISR (idt.c, vector 32) calls preempt_on_tick() with the current
 * task's full trap frame. We switch tasks *only* when the tick interrupted
 * ring-3 code: at that instant the task holds no kernel spinlock (spin_lock
 * disables interrupts, so the timer can't fire inside a critical section) and
 * its entire state is captured by the trap frame the CPU + isr_common_stub64
 * pushed onto its per-task kernel stack. A tick that lands in ring 0 (mid
 * syscall / interrupt handler) is never a switch point -- we just tick and
 * return -- which keeps the kernel effectively non-preemptible and avoids all
 * reentrancy hazards. Switching is a pure kernel-%rsp swap: save the current
 * frame pointer, load the next task's, and let the ISR epilogue pop+iretq into
 * it. No spinlock is taken here (interrupts are already disabled in the gate).
 * ------------------------------------------------------------------------- */

static volatile int preempt_enabled = 0;

/* Arm the timer switch. Called once the boot path is past its delicate
 * single-threaded init and a user task is (about to be) running. Until then a
 * tick only advances system_ticks. */
void sched_enable_preemption(void) {
    preempt_enabled = 1;
}

static inline uint64_t task_kstack_top(int id) {
    if (tasks[id].kernel_stack_top) return tasks[id].kernel_stack_top;
    return (uint64_t)&kernel_stacks[id][KERNEL_STACK_SIZE - 16];
}

/* Fabricate an initial, resumable interrupt trap frame at the top of task
 * `id`'s kernel stack, so the timer switch can iretq into a freshly spawned
 * user task exactly as if it had just been preempted at its entry point. cs/ss
 * are the 32-bit user segments (userspace is compatibility-mode), IF is set so
 * the task is itself preemptible, and all GP registers start zeroed. */
void sched_prepare_user_context(int id, uint64_t entry, uint64_t user_rsp) {
    if (id < 0 || id >= MAX_TASKS) return;
    uint64_t top = task_kstack_top(id) & ~0xFULL;
    struct interrupt_frame64 *f =
        (struct interrupt_frame64 *)(top - sizeof(struct interrupt_frame64));

    f->r15 = f->r14 = f->r13 = f->r12 = f->r11 = f->r10 = f->r9 = f->r8 = 0;
    f->rbp = f->rdi = f->rsi = f->rdx = f->rcx = f->rbx = f->rax = 0;
    f->int_no   = 0;
    f->err_code = 0;
    f->rip      = entry;
    f->cs       = 0x2b;          /* 32-bit user code (GDT 0x28 | RPL 3) */
    f->rflags   = 0x202;         /* IF set, reserved bit 1 */
    f->rsp      = user_rsp;
    f->ss       = 0x33;          /* 32-bit user data (GDT 0x30 | RPL 3) */

    tasks[id].saved_ksp     = (uint64_t)f;
    tasks[id].runnable_ctx  = 1;
}

#ifdef SMP
int this_cpu(void);   /* defined below */

/* Gate for cross-CPU task scheduling. APs come online and take timer ticks
 * immediately, but they only start *pulling runnable tasks* once the BSP has
 * populated the runnable pool and set this — which closes the window where an
 * AP could grab a task the BSP launched (via sched_enter_user) but not yet
 * claimed. Normal SMP boot leaves it 0 (APs idle, BSP runs the shell); the SMP
 * self-test turns it on after spawning its pool of workers. */
volatile int smp_sched_enabled = 0;

/* Raw test-and-set on the scheduler lock for use *inside* an interrupt handler,
 * where IF is already clear (the gate is an interrupt gate): unlike spin_lock()
 * it must not touch IF, or the ISR epilogue's iretq would race a re-entry. */
static void sched_raw_lock(void) {
    while (__sync_lock_test_and_set(&scheduler_lock.locked, 1))
        while (scheduler_lock.locked) __asm__ volatile ("pause");
}
static void sched_raw_unlock(void) { __sync_lock_release(&scheduler_lock.locked); }
#endif

/* Async signal delivery. When a ring-3 task is about to resume, redirect it into
 * its registered handler if SYS_SIGNAL queued one. The lowest-numbered *unmasked*
 * pending signal is delivered; masked signals stay queued until SYS_SIGMASK
 * unblocks them. Reuses the fault-signal path: try_deliver_fault_signal rewrites
 * the trap frame to enter the handler (signal number in ebx) and saves the
 * pre-signal frame for SYS_SIGRETURN. Left pending if the task is already inside a
 * handler (delivered after it returns; the in_signal guard lives in that helper). */
extern int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                                    uint32_t signum, uint64_t fault_addr);
static void deliver_pending_signal(uint64_t frame_ptr, int tid) {
    if (tid <= 0 || tid >= MAX_TASKS) return;
    uint32_t deliverable = tasks[tid].pending_sigs & ~tasks[tid].sig_mask;
    if (deliverable == 0) return;
    struct interrupt_frame64 *f = (struct interrupt_frame64 *)frame_ptr;
    if ((f->cs & 3) != 3) return;   /* only into a ring-3 frame */
    uint32_t sig = (uint32_t)__builtin_ctz(deliverable);   /* lowest pending signal (1..31) */
    if (try_deliver_fault_signal(f, tid, sig, 0)) {
        tasks[tid].pending_sigs &= ~(1u << sig);
    }
}

/* Called from the timer ISR. Returns the kernel %rsp the ISR epilogue should
 * resume on: the same frame when we don't switch, or the next task's saved
 * frame when we do. */
uint64_t preempt_on_tick(uint64_t frame_rsp, uint64_t interrupted_cs) {
    if (!preempt_enabled) return frame_rsp;
#ifndef SMP
    if ((interrupted_cs & 3) != 3) return frame_rsp;   /* only preempt ring 3 */

    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return frame_rsp;

    /* Deliver any signal queued for the running task before it resumes. */
    deliver_pending_signal(frame_rsp, cur);

    /* Round-robin: the next runnable user task (id != 0) with a resumable
     * context. */
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0 || cand == cur) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && tasks[cand].runnable_ctx
            && tasks[cand].saved_ksp) {
            next = cand;
            break;
        }
    }
    if (next < 0) return frame_rsp;   /* nobody else runnable -> keep running */

    /* Save the outgoing task's frame, install the incoming task's address
     * space + kernel stack, and hand its saved frame back to the ISR epilogue.
     * Kernel stacks and the task array live in the shared kernel mapping that
     * is present in every address space, so this stays valid across switch_cr3
     * even though we are still executing on the outgoing task's kernel stack. */
    tasks[cur].saved_ksp    = frame_rsp;
    tasks[cur].runnable_ctx = 1;

    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    current_kernel_stack_top = kstop;
    set_current_task(next);
    return tasks[next].saved_ksp;
#else
    /* SMP: any CPU may run any task, so selection + claim is serialised under the
     * scheduler lock and a task is only ever taken when task_running_cpu[] shows
     * it running nowhere. The shared runnable pool + this per-CPU pull is the
     * load-balancing mechanism: an idle AP grabs whatever work is available. The
     * BSP (cpu 0) is never pulled out of its ring-0 idle/kernel context by the
     * timer -- only its ring-3 tasks are preempted -- which preserves the exact
     * single-CPU boot flow; the APs do the multi-core work. */
    int cpu = this_cpu();
    if (!smp_sched_enabled) return frame_rsp;
    int ring3 = ((interrupted_cs & 3) == 3);
    if (!ring3 && cpu == 0) return frame_rsp;

    sched_raw_lock();
    int cur = percpu_current_task[cpu];

    /* Defensively claim the task we are currently running, so another CPU cannot
     * grab a task that was launched onto this CPU outside the timer path. */
    if (cur > 0 && cur < MAX_TASKS && task_running_cpu[cur] < 0)
        task_running_cpu[cur] = cpu;

    int next = -1;
    for (int i = 1; i <= MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 &&
            tasks[cand].runnable_ctx && tasks[cand].saved_ksp && task_running_cpu[cand] < 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) { sched_raw_unlock(); return frame_rsp; }   /* keep running cur */

    /* Save + release the outgoing task if it was a real user task in ring 3. A
     * ring-0 (idle) context is stateless and simply abandoned. */
    if (cur > 0 && cur < MAX_TASKS && ring3) {
        tasks[cur].saved_ksp    = frame_rsp;
        tasks[cur].runnable_ctx = 1;
        task_running_cpu[cur]   = -1;
    }

    task_running_cpu[next] = cpu;
    smp_cpus_ran_tasks |= (1u << cpu);
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    if (cpu == 0) current_kernel_stack_top = kstop;
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
    sched_raw_unlock();
    return ksp;
#endif
}

/* Block/switch with the concurrent-IPC publish order:
 *
 *   1. Write saved_ksp (the live trap frame) first.
 *   2. Full barrier so other CPUs observe the frame before the waiter.
 *   3. Publish the block (endpoint blocked_waiter / wait link / notif waiter
 *      + TASK_BLOCKED_* state) via ipc_publish_pending_block.
 *   4. Only then switch away.
 *
 * The previous order set BLOCKED + waiter in the syscall handler and saved the
 * frame only here — a reply on another CPU could patch a stale/null saved_ksp.
 * Syscall handlers now only set pending_block (+ object fields); this path
 * owns both the save and the publish. */
uint64_t ipc_block_switch(int blocked_task, uint64_t frame_rsp) {
    if (blocked_task <= 0 || blocked_task >= MAX_TASKS) return frame_rsp;

    /* (1) Frame first — wakers must never see a published waiter without this. */
    tasks[blocked_task].saved_ksp = frame_rsp;
    __sync_synchronize();

    /* (2) Publish waiter / BLOCKED state (or complete if already satisfied). */
    int must_switch = 1;
    if (tasks[blocked_task].pending_block != 0) {
        must_switch = ipc_publish_pending_block(blocked_task);
    } else {
        /* Legacy path: already in BLOCKED_* (should not happen for new code). */
        tasks[blocked_task].runnable_ctx = 0;
    }
    if (!must_switch) {
        /* Wait already satisfied with a valid frame; resume the same task. */
        return frame_rsp;
    }

#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
    task_running_cpu[blocked_task] = -1;   /* blocking: release it */

    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (blocked_task + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == TASK_RUNNABLE && tasks[cand].cr3 != 0 &&
                tasks[cand].runnable_ctx && tasks[cand].saved_ksp && task_running_cpu[cand] < 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        /* Nothing else runnable: un-publish and resume self (same fallback as
         * before — the caller retries from ring 3 once another task exists). */
        ipc_unpublish_block(blocked_task);
        task_running_cpu[blocked_task] = cpu;
        sched_raw_unlock();
        return frame_rsp;
    }

    task_running_cpu[next] = cpu;
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    if (cpu == 0) current_kernel_stack_top = kstop;
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
    sched_raw_unlock();
    return ksp;
#else
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (blocked_task + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == TASK_RUNNABLE && tasks[cand].cr3 != 0 &&
                tasks[cand].runnable_ctx && tasks[cand].saved_ksp) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        ipc_unpublish_block(blocked_task);
        return frame_rsp;
    }

    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    current_kernel_stack_top = kstop;
    set_current_task(next);

    return tasks[next].saved_ksp;
#endif
}


void print_boot_timestamp(void) {
    uint32_t ms = system_ticks;
    uint32_t sec = ms / 1000;
    uint32_t frac = ms % 1000;

    print("[ ");
    if (sec < 10) print("   ");
    else if (sec < 100) print("  ");
    else if (sec < 1000) print(" ");
    print_decimal(sec);
    print(".");
    if (frac < 10) print("00");
    else if (frac < 100) print("0");
    print_decimal(frac);
    print(" ] ");
}

/* Request a voluntary yield from a syscall handler. interrupt_handler64 sees
 * g_want_yield matching the caller and performs sched_yield_switch on the live
 * trap frame — the same full-context path as preemption and blocking IPC.
 * Never switches from mid-kernel cooperative code (that path is gone). */
volatile int g_want_yield = -1;

void yield(void) {
    g_want_yield = get_current_task();
}

/* Idle the current CPU. The only way between tasks is the full-context path
 * (timer preemption, ipc_block_switch, sched_yield_switch, sched_enter_user). */
void __attribute__((noreturn)) kernel_idle(void) {
    for (;;) __asm__ volatile ("sti; hlt");
}

/* Enter a task that already has a fabricated/saved full trap frame
 * (sched_prepare_user_context / do_spawn). Installs CR3, TSS RSP0, and current
 * task, then runs the same pop+iretq epilogue as isr_common_stub64 so first
 * entry matches every later resume. Does not return. */
void __attribute__((noreturn)) sched_enter_user(int tid) {
    if (tid <= 0 || tid >= MAX_TASKS ||
        !tasks[tid].runnable_ctx || !tasks[tid].saved_ksp || !tasks[tid].cr3) {
        kernel_idle();
    }

#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
    task_running_cpu[tid] = cpu;
#endif
    switch_cr3(tasks[tid].cr3);
    uint64_t kstop = task_kstack_top(tid);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(tid);
    uint64_t ksp = tasks[tid].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif

    /* Mirror isr_common_stub64's epilogue: load the saved frame as %rsp first
     * (before clobbering any GPRs with segment selectors), set user data
     * segments, pop GPRs, skip int_no/err_code, iretq into ring 3. */
    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "mov $0x33, %%ax\n\t"
        "mov %%ax, %%ds\n\t"
        "mov %%ax, %%es\n\t"
        "mov %%ax, %%fs\n\t"
        "mov %%ax, %%gs\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%r11\n\t"
        "popq %%r10\n\t"
        "popq %%r9\n\t"
        "popq %%r8\n\t"
        "popq %%rbp\n\t"
        "popq %%rdi\n\t"
        "popq %%rsi\n\t"
        "popq %%rdx\n\t"
        "popq %%rcx\n\t"
        "popq %%rbx\n\t"
        "popq %%rax\n\t"
        "addq $16, %%rsp\n\t"
        "iretq\n\t"
        :: "r"(ksp) : "memory", "cc", "rax"
    );
    __builtin_unreachable();
}

/* Voluntary yield with a live trap frame (SYS_YIELD). Save the caller's frame
 * and switch to another runnable user task if one exists; otherwise resume the
 * same frame. Returns the kernel %rsp for the ISR epilogue. */
uint64_t sched_yield_switch(int cur, uint64_t frame_rsp) {
    if (cur <= 0 || cur >= MAX_TASKS) return frame_rsp;

#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
#endif
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0 || cand == cur) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 &&
            tasks[cand].runnable_ctx && tasks[cand].saved_ksp
#ifdef SMP
            && task_running_cpu[cand] < 0
#endif
           ) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
#ifdef SMP
        sched_raw_unlock();
#endif
        return frame_rsp;
    }

    tasks[cur].saved_ksp    = frame_rsp;
    tasks[cur].runnable_ctx = 1;
#ifdef SMP
    task_running_cpu[cur]   = -1;
    task_running_cpu[next]  = cpu;
#endif
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif
    return ksp;
}

/* Terminate task `id`: wake a SYS_WAIT waiter blocked on it, drop its signal
 * handler, mark it dead, and (SMP) release its running-CPU guard so no core will
 * reselect it. The caller (SYS_EXIT / SYS_KILL) is responsible for switching the
 * CPU away from the task if it happens to be the one currently running. */
void task_teardown(int id) {
    if (id <= 0 || id >= MAX_TASKS) return;

    int w = tasks[id].waiter;
    if (w >= 0 && w < MAX_TASKS) {
        /* Unblock a SYS_WAIT waiter: make it runnable and resumable so the
         * scheduler resumes it via the trap frame ipc_block_switch saved when it
         * blocked (it returns from SYS_WAIT with eax already 0). */
        if (tasks[w].state == TASK_BLOCKED_WAIT) {
            tasks[w].state        = TASK_RUNNABLE;
            tasks[w].runnable_ctx = 1;
        }
        tasks[id].waiter = -1;
    }

    tasks[id].sig_handler = 0;
    tasks[id].in_signal   = 0;
    tasks[id].sig_altstack_sp   = 0;   /* clear so a reused slot never inherits a stale altstack */
    tasks[id].sig_altstack_size = 0;
    tasks[id].sig_on_stack      = 0;
    tasks[id].state       = 0;   /* dead: the scheduler will not select it */
    tasks[id].runnable_ctx = 0;  /* and it has no resumable context any more */
    tasks[id].saved_ksp    = 0;
#ifdef SMP
    task_running_cpu[id]  = -1;  /* release the SMP mutual-exclusion guard */
#endif
}

/* Switch away from a task that has just terminated (SYS_EXIT / SYS_KILL-self),
 * called from interrupt_handler64 with the dead task's trap frame. The dead
 * frame is abandoned (not saved); we resume the next runnable task via its saved
 * trap frame — the same iretq mechanism the timer and blocking IPC use — and
 * return its kernel %rsp for the ISR epilogue. Returns 0 if nothing else is
 * runnable, so the caller can fall back to the kernel idle/reaper. */
uint64_t task_exit_switch(int dead) {
#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
#endif
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (dead + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && tasks[cand].runnable_ctx
            && tasks[cand].saved_ksp
#ifdef SMP
            && task_running_cpu[cand] < 0
#endif
           ) { next = cand; break; }
    }
    if (next < 0) {
#ifdef SMP
        sched_raw_unlock();
#endif
        return 0;   /* nothing else to run — caller idles */
    }
#ifdef SMP
    task_running_cpu[next] = cpu;
#endif
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif
    return ksp;
}

/* Enter task `t` via the fresh ring-3 context sched_prepare_user_context just
 * fabricated for it — used by SYS_EXEC_NAMED, which replaced the task's image in
 * place. Mirrors task_exit_switch's tail (install the address space + kernel
 * stack, hand the saved frame to the ISR epilogue) but re-enters the *same* task
 * rather than switching away. Returns the kernel %rsp for the ISR epilogue. */
uint64_t exec_reenter_switch(int t) {
    if (t <= 0 || t >= MAX_TASKS) return 0;
#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
    task_running_cpu[t] = cpu;
#endif
    switch_cr3(tasks[t].cr3);
    uint64_t kstop = task_kstack_top(t);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(t);
    uint64_t ksp = tasks[t].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif
    return ksp;
}

int this_cpu(void) {

    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    uint32_t id_reg = lapic[0x20 / 4];
    uint32_t cpu = (id_reg >> 24) & 0xFF;
    if (cpu >= MAX_CPUS) cpu = 0;
    return (int)cpu;
}

int get_current_task(void) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    return percpu_current_task[c];
}

void set_current_task(int v) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    percpu_current_task[c] = v;

    if (c == 0) current_task = v;

    /* Keep this CPU's TSS I/O-permission bitmap in step with the task about to
     * run: a driver task's granted CAP_IO_PORT windows are opened, every other
     * task runs with all ports denied. We read the task's pre-built io-port cache
     * (populated by cap_cache_io_ports on grant) *without* taking cap_lock — this
     * runs in the ISR/switch path with interrupts already off, and spin_unlock
     * would sti at depth 0 and re-enable interrupts mid-switch. The cache is only
     * mutated in normal cap-grant/teardown context, so a lock-free read here is a
     * stale-tolerant hint on top of the authoritative capability system (SMP: a
     * torn read at worst mis-sets a bit for one quantum; the cap system still
     * gates every operation). */
    const tcb_t *t = (v >= 0 && v < MAX_TASKS && tasks[v].cspace) ? &tasks[v] : 0;
    tss_load_io_bitmap(c, t);
}

void scheduler_lock_acquire(void) { spin_lock(&scheduler_lock); }
void scheduler_lock_release(void) { spin_unlock(&scheduler_lock); }


static volatile int irq_lock_depth = 0;

/*
 * Capability seqlock counter (audit finding 3.1: lockless `cap_lookup` vs. a
 * concurrent capability mutation on another CPU).
 *
 * EVERY capability mutation already runs under `cap_lock` (cap_mint/transfer/
 * revoke, the system-wide revoke sweep, cap_install_from_root, the spawn/sudo
 * cspace endowments, SYS_CAP_GRANT). To let the read side — `cap_lookup`, which
 * is DELIBERATELY lock-free so the kill/grant/signal paths can nest it inside a
 * `cap_lock` critical section without a non-recursive self-deadlock — observe a
 * torn-free snapshot, we make holding `cap_lock` bump this counter: odd while a
 * `cap_lock` section is in flight, even when the cap state is stable. Tying the
 * bump to the lock itself (rather than to each mutator) means no present or
 * FUTURE writer can forget it, provided it obeys the existing "mutate caps only
 * under cap_lock" invariant.
 *
 * `cap_lookup` reads this before and after its field reads and retries on an
 * odd/changed value (a standard seqlock reader). On the single-core default no
 * cap write ever runs concurrently with a lock-free reader (writes hold cap_lock
 * with interrupts masked, and no ISR mutates caps), so the counter stays even
 * and the reader never retries; the machinery only does work under SMP.
 */
uint32_t cap_seq = 0;

void spin_lock(spinlock_t *lock) {
    __asm__ volatile ("cli" ::: "memory");
    irq_lock_depth++;
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        while (lock->locked) { __asm__ volatile ("pause" ::: "memory"); }
    }
    /* Enter a cap_lock critical section: seq -> odd, ordered after the acquire
     * so a lock-free reader either sees odd (and retries) or has already taken a
     * stable snapshot before this write began. */
    if (lock == &cap_lock) {
        __atomic_fetch_add(&cap_seq, 1, __ATOMIC_SEQ_CST);
    }
}
void spin_unlock(spinlock_t *lock) {
    /* Leave a cap_lock critical section: seq -> even, ordered before the release
     * so all cspace writes in the section are visible to a reader that then
     * observes the even count. */
    if (lock == &cap_lock) {
        __atomic_fetch_add(&cap_seq, 1, __ATOMIC_SEQ_CST);
    }
    __sync_lock_release(&lock->locked);

    if (irq_lock_depth > 0 && --irq_lock_depth == 0) {
        __asm__ volatile ("sti" ::: "memory");
    }
}

