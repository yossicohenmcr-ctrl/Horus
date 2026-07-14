#include "syscall_internal.h"

/* ------------------------------------------------------------------------- *
 *  Per-syscall handlers.
 *
 *  Each handler is the extracted body of one dispatch case, so the switch in
 *  syscall_handler() is a thin table of one-liners and every syscall can be
 *  audited in isolation. This is a behaviour-preserving move: switch-level
 *  `break` became `return` (inner loop break/continue are unchanged), and the
 *  shared in_kernel bookkeeping still brackets the dispatch in syscall_handler.
 * ------------------------------------------------------------------------- */

/* SYS_GET_LINE (3): read a line from the console into the caller's buffer. */
static void h_get_line(struct regs *r) {
    struct capability *c = cap_lookup(8, CAP_RIGHT_READ);
    if (!c) c = cap_lookup(3, CAP_RIGHT_READ);
    if (!c) { r->eax = -1; return; }

    void *user_dest = (void *)(addr_t)r->ebx;
    uint32_t max_len = 127;
    char line[128];
    uint32_t len = 0;
    char ch;

    while (len < max_len) {
        ch = console_getc();

        if (ch == '\r' || ch == '\n') {
            print("\n");
            break;
        }

#ifdef DEBUG_SHELL
        if (ch == 0x1B) {
            /* Spin for serial — do not cooperative-yield mid-syscall. */
            while ((inb(0x3FD) & 1) == 0) { __asm__ volatile ("pause"); }
            char seq1 = inb(0x3F8);
            while ((inb(0x3FD) & 1) == 0) { __asm__ volatile ("pause"); }
            char seq2 = inb(0x3F8);

            if (seq1 == '[') {
                if (seq2 == 'A') {
                    if (history_count > 0) {
                        if (history_pos < 0) history_pos = history_count - 1;
                        else if (history_pos > 0) history_pos--;

                        for (uint32_t i = 0; i < len; i++) {
                            print("\b \b");
                        }
                        len = 0;
                        while (cmd_history[history_pos][len] && len < max_len - 1) {
                            line[len] = cmd_history[history_pos][len];
                            char echo[2] = {line[len], 0};
                            print(echo);
                            len++;
                        }
                        line[len] = 0;
                    }
                } else if (seq2 == 'B') {
                    if (history_pos >= 0) {
                        history_pos++;
                        if (history_pos >= history_count) {
                            history_pos = -1;
                            for (uint32_t i = 0; i < len; i++) print("\b \b");
                            len = 0;
                            line[0] = 0;
                        } else {
                            for (uint32_t i = 0; i < len; i++) print("\b \b");
                            len = 0;
                            while (cmd_history[history_pos][len] && len < max_len - 1) {
                                line[len] = cmd_history[history_pos][len];
                                char echo[2] = {line[len], 0};
                                print(echo);
                                len++;
                            }
                            line[len] = 0;
                        }
                    }
                }
            }
            continue;
        }
#endif
        if ((unsigned char)ch < 32 && ch != '\b' && ch != 0x7F) {
            continue;
        }

        if (ch == '\b' || ch == 0x7F) {
            if (len > 0) {
                len--;
                print("\b \b");
            }
            continue;
        }

        char echo[2] = {ch, 0};
        print(echo);
        line[len++] = ch;
    }

    line[len] = 0;

#ifdef DEBUG_SHELL
    if (len > 0) {
        if (history_count == HISTORY_SIZE) {
            for (int i = 0; i < HISTORY_SIZE - 1; i++) {
                for (int j = 0; j < CMD_MAX; j++) {
                    cmd_history[i][j] = cmd_history[i+1][j];
                }
            }
            history_count--;
        }
        for (uint32_t j = 0; j < CMD_MAX && j <= len; j++) {
            cmd_history[history_count][j] = line[j];
        }
        history_count++;
    }
    history_pos = -1;
#endif

    if (copy_to_user(user_dest, line, len + 1) != 0) {
        r->eax = -1;
    } else {
        r->eax = len;
    }
}

/* SYS_GET_SYSINFO (6): copy a zero-padded version string to the caller. */
static void h_sysinfo(struct regs *r) {
    const char *info = "Horus v0.4 | per-task paging + cspaces | Rust validators";
    /* Copy a zero-padded fixed-size buffer rather than 64 bytes straight
     * off the string literal: the literal is shorter than 64 bytes, so
     * the old copy leaked ~7 bytes of adjacent .rodata to userspace. */
    char infobuf[64];
    size_t ii = 0;
    for (; ii < sizeof(infobuf) - 1 && info[ii]; ii++) infobuf[ii] = info[ii];
    for (; ii < sizeof(infobuf); ii++) infobuf[ii] = 0;
    if (copy_to_user((void*)(addr_t)r->ebx, infobuf, sizeof(infobuf)) == 0) {
        r->eax = 0;
    } else {
        r->eax = -1;
    }
}

/* SYS_SBRK (10): increment the program break by `increment` bytes.
 * Returns the OLD break (pointer to start of newly allocated region) on
 * success, or (uint32_t)-1 on failure.  heap_end grows on demand up to
 * USER_HEAP_MAX_SIZE; the demand pager allocates physical pages lazily. */
static void h_sbrk(struct regs *r) {
    int tid = get_current_task();
    int32_t increment = (int32_t)r->ebx;
    if (increment == 0) { r->eax = tasks[tid].heap_current; return; }

    uint32_t new_current = tasks[tid].heap_current + (uint32_t)increment;
    uint32_t heap_max    = tasks[tid].heap_start + USER_HEAP_MAX_SIZE;

    /* Never let the heap grow up into the kernel's always-live low-memory state:
     * the kernel is linked low, so a user page mapped at/above this floor would
     * shadow kernel data (tasks[], page tables, cspaces) on this task's own CR3
     * and corrupt the kernel. Bounds the heap to the safe region below it. */
    uint32_t kfloor = kernel_lowmem_critical_floor();
    if (heap_max > kfloor) heap_max = kfloor;

    if (new_current < tasks[tid].heap_start || new_current > heap_max) {
        r->eax = (uint32_t)-1;
        return;
    }
    /* Extend the authorised ceiling on demand; physical pages arrive lazily. */
    if (new_current > tasks[tid].heap_end) {
        uint32_t new_end = (new_current + 0xFFFU) & ~0xFFFU;
        if (new_end > heap_max) new_end = heap_max;
        tasks[tid].heap_end = new_end;
    }
    uint32_t old = tasks[tid].heap_current;
    tasks[tid].heap_current = new_current;
    r->eax = old;
}

/* SYS_BRK (62): set the program break to an absolute address.
 * Returns the new break on success.  On failure (addr out of range) returns
 * the unchanged current break — callers check return == addr to detect error,
 * matching the Linux brk(2) convention.  addr=0 queries without changing. */
static void h_brk(struct regs *r) {
    int tid = get_current_task();
    uint32_t addr     = r->ebx;
    uint32_t heap_max = tasks[tid].heap_start + USER_HEAP_MAX_SIZE;

    /* Keep the heap clear of the kernel's always-live low-memory state (see h_sbrk). */
    uint32_t kfloor = kernel_lowmem_critical_floor();
    if (heap_max > kfloor) heap_max = kfloor;

    if (addr == 0) { r->eax = tasks[tid].heap_current; return; }

    if (addr < tasks[tid].heap_start || addr > heap_max) {
        r->eax = tasks[tid].heap_current;   /* failure: return unchanged break */
        return;
    }
    uint32_t aligned = (addr + 0xFFFU) & ~0xFFFU;
    if (aligned > heap_max) aligned = heap_max;
    tasks[tid].heap_current = aligned;
    tasks[tid].heap_end     = aligned;
    r->eax = aligned;
}

/* SYS_WRITE (11): write to fd 1 (console). Length clamped to the scratch buf. */
static void h_write(struct regs *r) {
    int fd = r->ebx;
    void *buf = (void*)(addr_t)r->ecx;
    size_t len = r->edx;

    if (fd != 1) { r->eax = -1; return; }

    char kbuf[256];
    size_t to_copy = len > 255 ? 255 : len;
    if (copy_from_user(kbuf, buf, to_copy) != 0) {
        r->eax = -1;
        return;
    }
    kbuf[to_copy] = 0;
    print(kbuf);
    r->eax = to_copy;
}

/* SYS_READ (12): read from fd 0 (console line) or fd>=3 (ramfs, needs slot-3 read). */
static void h_read(struct regs *r) {
    int fd = r->ebx;
    void *buf = (void*)(addr_t)r->ecx;
    size_t len = r->edx;

    if (fd == 0) {
        char line[128];
        uint32_t got = 0;
        while (got < len && got < 127) {
            char ch = console_getc();
            if (ch == '\r' || ch == '\n') { print("\n"); break; }
            if (ch == '\b' || ch == 0x7F) { if (got > 0) { got--; print("\b \b"); } continue; }
            char echo[2] = {ch, 0}; print(echo);
            line[got++] = ch;
        }
        line[got] = 0;
        if (copy_to_user(buf, line, got + 1) != 0) r->eax = (uint32_t)SYS_ERR_FAULT;
        else r->eax = got;
    } else if (fd >= 3) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
        if (!c) { r->eax = -1; return; }
        char kbuf[256];
        size_t to_read = len > 255 ? 255 : len;
        int n = ramfs_read(fd, kbuf, to_read);
        if (n > 0) {
            if (copy_to_user(buf, kbuf, n) == 0) r->eax = n;
            else r->eax = -1;
        } else {
            r->eax = n;
        }
    } else {
        r->eax = -1;
    }
}

/* SYS_EXEC (14): create a task at an already-loaded image.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_exec(struct regs *r) {
    uint32_t load_base = r->ebx;
    uint32_t entry_offset = r->ecx;
    (void)(r->edx);

    /* Guard against uint32 overflow: a crafted (load_base, entry_offset) pair
     * whose sum wraps around could yield an entry point at an arbitrary address.
     * The resulting task would fault immediately (paging enforces ring separation),
     * but the overflow is confusing and could mask future bugs. */
    if ((uint64_t)load_base + entry_offset >= USER_MAX_VADDR) {
        r->eax = -1;
        return;
    }

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) {
        r->eax = -1;
        return;
    }

    /* Premap stays at the fixed base (this path loads a non-relocated image);
     * the user-supplied load_base only drives the entry/eip, as before. */
    create_task(new_id, load_base + entry_offset, DEMO_TASK_STACK_TOP, USER_AREA_BASE);

    tasks[new_id].heap_start = USER_HEAP_BASE + new_id * 0x10000;
    tasks[new_id].heap_current = tasks[new_id].heap_start;
    tasks[new_id].heap_end = tasks[new_id].heap_start + 0x10000;

    tasks[new_id].name[0] = 's'; tasks[new_id].name[1] = 'p';
    tasks[new_id].name[2] = 'a'; tasks[new_id].name[3] = 'w';
    tasks[new_id].name[4] = 'n'; tasks[new_id].name[5] = '0' + new_id;
    tasks[new_id].name[6] = 0;

    r->eax = new_id;
}

/* SYS_FS_LIST (16): list ramfs entries, honouring the caller's buffer size.
 * Capability (slot 3, READ) is enforced centrally by the dispatch table. */

static void h_exit(struct regs *r) {
    task_teardown(get_current_task());
    r->eax = 0;
}

/* Return non-zero if the current task may terminate `target`: either it holds a
 * CAP_TCB capability to the target with WRITE rights (every task has one to
 * itself at slot 0; a spawner is granted one per child in do_spawn), or it holds
 * CAP_USER admin authority (slot 6). */
static int task_kill_authorized(int target) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return 0;

    /* Called only from inside a cap_lock critical section (h_kill / h_signal),
     * so use the non-retrying lookup — the seqlock reader would spin on the odd
     * seq our own cap_lock section set. */
    struct capability *admin = cap_lookup_locked(6, CAP_RIGHT_ALL);
    if (admin && admin->type == CAP_USER) return 1;

    capability_t *cs = tasks[cur].cspace;
    if (!cs) return 0;
    for (uint32_t s = 0; s < tasks[cur].cspace_size; s++) {
        if (cs[s].type == CAP_TCB && cs[s].object == (uint64_t)target &&
            (cs[s].rights & CAP_RIGHT_WRITE)) {
            return 1;
        }
    }
    return 0;
}

/* SYS_KILL (63): terminate task ebx. Authorised by a CAP_TCB capability to the
 * target (or CAP_USER admin) — enforced in the handler because the target is
 * dynamic, so the central slot-based gate cannot express it. Killing yourself
 * behaves like SYS_EXIT (interrupt_handler64 redirects on the state==0 return). */
static void h_kill(struct regs *r) {
    int target = (int)r->ebx;
    if (target <= 0 || target >= MAX_TASKS || tasks[target].state == 0) {
        r->eax = (uint32_t)SYS_ERR_INVAL;
        return;
    }
    /* Authorize and terminate as ONE cap_lock critical section. Revocation
     * (SYS_CAP_REVOKE / cap_revoke_global) always runs under cap_lock, so
     * holding it here means a concurrent revoke on another CPU cannot land
     * between the authority check and the teardown and strip the CAP_TCB/admin
     * cap we just validated (the SMP TOCTOU on raw cap pointers). task_teardown
     * takes no locks, so bracketing it with cap_lock cannot deadlock; the lookup
     * (via task_kill_authorized) uses cap_lookup_locked, the non-retrying variant,
     * so it neither recurses on cap_lock nor spins on the seq this section set. */
    spin_lock(&cap_lock);
    if (!task_kill_authorized(target)) {
        spin_unlock(&cap_lock);
        r->eax = (uint32_t)SYS_ERR_PERM;
        return;
    }
    task_teardown(target);
    spin_unlock(&cap_lock);
    r->eax = 0;
}

/* A deliverable signal for a task blocked in SYS_WAIT must interrupt the wait so
 * the handler runs promptly, rather than only when the awaited task eventually
 * exits (which may be never). Rewrite the blocked task's saved SYS_WAIT trap
 * frame to return SYS_ERR_INTR, drop the back-link from whatever it was waiting
 * on (so that task's teardown won't also try to wake it), and make it runnable.
 * It resumes from the wait with EINTR, and the queued signal is then delivered on
 * its return to ring 3 (deliver_pending_signal). */
static void signal_interrupt_wait(int t) {
    struct interrupt_frame64 *f = (struct interrupt_frame64 *)tasks[t].saved_ksp;
    if (!f) return;
    f->rax = (uint64_t)(uint32_t)SYS_ERR_INTR;
    for (int w = 1; w < MAX_TASKS; w++) {
        if (tasks[w].waiter == t) { tasks[w].waiter = -1; break; }
    }
    tasks[t].state        = TASK_RUNNABLE;
    tasks[t].runnable_ctx = 1;
}

/* SYS_SIGNAL (66): send signal `ecx` to task `ebx`. Same authority as SYS_KILL —
 * a CAP_TCB to the target (or CAP_USER admin), enforced here since the target is
 * dynamic. If the target registered a handler it is delivered asynchronously:
 * the signal is queued in pending_sigs and the lowest-numbered *unmasked* one is
 * consumed when the task is next resumed to ring 3, redirecting it into its
 * handler (see preempt_on_tick / try_deliver_fault_signal). A masked signal stays
 * pending until SYS_SIGMASK unblocks it. With no handler — or for the uncatchable
 * SIG_KILL — the default action applies and the target is terminated. Signalling
 * yourself is permitted (self-TCB). */
static void h_signal(struct regs *r) {
    int target      = (int)r->ebx;
    uint32_t signum = r->ecx;
    if (target <= 0 || target >= MAX_TASKS || tasks[target].state == 0) {
        r->eax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (signum == 0 || signum > SIG_MAX) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    /* Authorize + deliver as ONE cap_lock critical section, exactly as SYS_KILL:
     * a concurrent revoke (always under cap_lock) then cannot strip the
     * authorizing cap between the check and the effect (SMP TOCTOU). The effect
     * — task_teardown, the pending_sigs store, and signal_interrupt_wait — takes
     * no locks, so holding cap_lock across it cannot deadlock. */
    spin_lock(&cap_lock);
    if (!task_kill_authorized(target)) {
        spin_unlock(&cap_lock);
        r->eax = (uint32_t)SYS_ERR_PERM; return;
    }

    if (signum == SIG_KILL || tasks[target].sig_handler == 0) {
        task_teardown(target);                 /* default action: terminate */
    } else {
        tasks[target].pending_sigs |= (1u << signum);   /* async: delivered on next resume */
        /* If it's parked in SYS_WAIT and this signal isn't masked, interrupt the
         * wait so the handler runs promptly instead of waiting on the target. */
        if (tasks[target].state == TASK_BLOCKED_WAIT &&
            !(tasks[target].sig_mask & (1u << signum))) {
            signal_interrupt_wait(target);
        }
    }
    spin_unlock(&cap_lock);
    r->eax = 0;
}

/* SYS_WAIT (17): block until task `tid` exits.
 *
 * Records a pending block only; ipc_block_switch saves the trap frame first and
 * only then sets tasks[tid].waiter + TASK_BLOCKED_WAIT so a concurrent teardown
 * cannot wake a task whose saved_ksp is not yet the SYS_WAIT frame. */
static void h_wait(struct regs *r) {
    int cur = get_current_task();
    int tid = r->ebx;
    if (tid < 0 || tid >= MAX_TASKS || tid == cur) { r->eax = (uint32_t)-1; return; }
    if (tasks[tid].state == TASK_DEAD) { r->eax = 0; return; }  /* already gone: satisfied */

    /* Intent only — not wake-visible until ipc_publish_pending_block. */
    tasks[cur].blocked_on    = tid;
    tasks[cur].pending_block = TASK_BLOCKED_WAIT;
    r->eax = 0;   /* the value the caller sees once task_teardown wakes it */
}

/* SYS_GET_TASK_INFO (18): report task_info for `tid` (self, or any with admin/audit). */
static void h_task_info(struct regs *r) {
    int tid = r->ebx;
    struct task_info *out = (struct task_info*)(addr_t)r->ecx;

    if (tid < 0 || tid >= MAX_TASKS) {
        r->eax = -1;
        return;
    }

    int is_privileged = 0;
    struct capability *c = cap_lookup(6, CAP_RIGHT_ALL);
    if (c && c->type == CAP_USER) is_privileged = 1;
    if (!is_privileged) {
        c = cap_lookup(7, CAP_RIGHT_READ);
        if (c && c->type == CAP_AUDIT) is_privileged = 1;
    }
    /* root (uid 0) is the system administrator and may inspect every task, the
     * same uid==0 authority the block/object-store syscalls enforce. This is what
     * lets the root shell's `ps` list the servers init launched, even though the
     * shell was not delegated a CAP_USER/CAP_AUDIT of its own. */
    if (!is_privileged && tasks[get_current_task()].uid == 0) is_privileged = 1;

    if (!is_privileged && tid != get_current_task()) {
        r->eax = -3;
        return;
    }

    struct task_info info;
    for (size_t z = 0; z < sizeof(info); z++) ((uint8_t*)&info)[z] = 0;
    info.id = tid;
    info.state = tasks[tid].state;
    info.uid = tasks[tid].uid;
    info.gid = tasks[tid].gid;
    /* Do NOT leak the page-table physical base to ring-3: it reveals
     * the physical memory layout and aids exploitation. Field is kept
     * for ABI stability but always reported as 0; no consumer uses it. */
    info.cr3 = 0;
    info.heap_used = tasks[tid].heap_current - tasks[tid].heap_start;
    for (int k = 0; k < 31 && tasks[tid].name[k]; k++)
        info.name[k] = tasks[tid].name[k];
    info.name[31] = 0;
    info.eip = tasks[tid].eip;
    info.blocked_on = tasks[tid].blocked_on;
    info.blocked_on_notif = tasks[tid].blocked_on_notif;
    info.in_kernel = tasks[tid].in_kernel;
    info.caps_in_use = tasks[tid].caps_in_use;

    if (copy_to_user(out, &info, sizeof(info)) == 0) r->eax = 0;
    else r->eax = (uint32_t)SYS_ERR_FAULT;
}

/* SYS_RUN (19): drop the current task to ring 3 at an already-loaded image.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_run(struct regs *r) {
    uint32_t load_base = r->ebx;
    uint32_t entry = r->ecx;

    tasks[get_current_task()].heap_current = tasks[get_current_task()].heap_start;

    if (get_current_task() == 0) {
        r->eax = -1;
        return;
    }
    /* Guard uint32 overflow same as h_exec. */
    if ((uint64_t)load_base + entry >= USER_MAX_VADDR) {
        r->eax = -1;
        return;
    }
    drop_to_ring3(load_base + entry, tasks[get_current_task()].esp);
    r->eax = 0;
}

/* SYS_RECEIVE_PROGRAM: stage a program image and return its header.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_receive_program(struct regs *r) {
    void *user_hdr = (void *)(addr_t)r->ebx;
    struct program_header k_hdr;

    int rc = do_receive_program(&k_hdr);
    if (rc != 0) {
        r->eax = rc;
        return;
    }

    if (user_hdr) {
        if (copy_to_user(user_hdr, &k_hdr, sizeof(k_hdr)) != 0) {
            r->eax = -3;
            return;
        }
    }

    r->eax = 0;
}

/* SYS_AUTH: authenticate the calling task as a user (sets uid/gid on success). */

/* SYS_YIELD: request a full-context switch; interrupt_handler64 runs
 * sched_yield_switch on the live trap frame after this returns. */
static void h_yield(struct regs *r) {
    yield();
    r->eax = 0;
}

/* cap mint/transfer/move/revoke (4/8/9/51): authority enforced inside the
 * cap_* primitives (caller_has_authority + per-right checks). */
static void h_cap_mint(struct regs *r) {
    bool ok = cap_mint(r->ebx, r->ecx, r->edx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_MINT, r->ebx, ok ? 0 : -1, ok ? "cap mint" : "cap mint denied");
}
static void h_cap_transfer(struct regs *r) {
    bool ok = cap_transfer(r->ebx, r->ecx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_TRANSFER, r->ebx, ok ? 0 : -1, ok ? "cap transfer" : "cap transfer denied");
}
static void h_cap_move(struct regs *r) {
    bool ok = cap_move(r->ebx, r->ecx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_TRANSFER, r->ebx, ok ? 0 : -1, ok ? "cap move" : "cap move denied");
}
static void h_cap_revoke(struct regs *r) {
    /* The authoritative rights check (CAP_RIGHT_REVOKE on the target, kernel
     * exempt) and the no-ambient-authority guard live in cap_revoke(). */
    bool ok = cap_revoke(r->ebx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_REVOKE, r->ebx, ok ? 0 : -1, ok ? "cap revoke" : "cap revoke denied");
}

/* SYS_CAP_GRANT (65): delegate a capability into a supervised child's cspace.
 * Copy the caller's capability at `src_slot` into tasks[target]'s cspace at
 * `dest_slot` with a fresh serial (so the grantee's cap_lookup accepts it),
 * preserving type/rights/object/badge/generation so the delegated copy tracks the
 * same lineage — a later revoke of the object invalidates it too. Authorised by a
 * CAP_TCB (WRITE) to the target (the spawner's per-child cap) or CAP_USER admin,
 * exactly like SYS_KILL: a task may only push capabilities down into children it
 * supervises (no ambient authority upward). The target must be a live task other
 * than the caller. The caller can only delegate a capability it actually holds. */
static void h_cap_grant(struct regs *r) {
    int cur = get_current_task();
    int target = (int)r->ebx;
    uint32_t src_slot  = r->ecx;
    uint32_t dest_slot = r->edx;

    if (target <= 0 || target >= MAX_TASKS || target == cur || tasks[target].state == 0) {
        r->eax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (src_slot >= CNODE_SIZE || dest_slot >= CNODE_SIZE) {
        r->eax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (!tasks[cur].cspace || !tasks[target].cspace) {
        r->eax = (uint32_t)SYS_ERR_INVAL; return;
    }
    /* Allocate the fresh serial up-front: cap_alloc_fresh_serial() grabs cap_lock
     * itself and the lock is not recursive, so it must run OUTSIDE the critical
     * section below. A serial burned on a subsequently-denied grant is harmless
     * (serials are freshness tokens from a wrapping counter, not a scarce id). */
    uint32_t fresh = cap_alloc_fresh_serial();

    /* Authorize, snapshot the source, and install into the target as ONE cap_lock
     * critical section. Revocation always runs under cap_lock, so a concurrent
     * revoke on another CPU cannot (a) strip the CAP_TCB/admin authority between
     * the check and the install, nor (b) invalidate `src` between the lookup and
     * the copy (the SMP TOCTOU on raw cap pointers). We call the non-retrying
     * cap_lookup_locked below (the public seqlock reader would spin on the odd
     * seq this cap_lock section set); audit_log runs after the unlock so no
     * audit-subsystem lock nests under cap_lock. */
    spin_lock(&cap_lock);
    /* Same authority as SYS_KILL: a CAP_TCB to the target, or admin. */
    if (!task_kill_authorized(target)) {
        spin_unlock(&cap_lock);
        audit_log(AUDIT_CAP_TRANSFER, (uint32_t)target, -1, "cap grant denied");
        r->eax = (uint32_t)SYS_ERR_PERM; return;
    }
    /* The source must be a live capability the caller actually holds. */
    struct capability *src = cap_lookup_locked(src_slot, 0);
    if (!src || src->type == CAP_NULL) {
        spin_unlock(&cap_lock);
        r->eax = (uint32_t)SYS_ERR_NOENT; return;
    }
    capability_t granted = *src;
    granted.serial = fresh;
    tasks[target].cspace[dest_slot] = granted;
    spin_unlock(&cap_lock);

    audit_log(AUDIT_CAP_TRANSFER, (uint32_t)target, 0, "cap grant");
    r->eax = 0;
}

/* clear screen (5): slot-3 WRITE enforced by the table. */
static void h_clear(struct regs *r) {
    clear_screen();
    r->eax = 0;
}

/* debug command exec (7): only meaningful under DEBUG_SHELL. */
static void h_debug_exec(struct regs *r) {
    char cmd[128];
    if (copy_from_user(cmd, (void*)(addr_t)r->ebx, 127) != 0) {
        r->eax = -1;
        return;
    }
    cmd[127] = 0;
#ifdef DEBUG_SHELL
    r->eax = process_user_command(cmd);
#else
    r->eax = -1;
#endif
}

/* ramfs open (13): slot-3 READ enforced by the table. */

static void h_getuid(struct regs *r) {
    r->eax = tasks[get_current_task()].uid;
}

/* SYS_SIGACTION: register (handler != 0) or clear (handler == 0) THIS task's own
 * fault-signal handler. Self-authority only -- a task sets a handler for itself,
 * never for another (async cross-task signals would need a capability on the
 * target's TCB, which this does not provide). The handler entry is validated
 * against the user code window in safe Rust so a fault can only ever redirect
 * ring-3 control flow to plausible user code. */
static void h_sigaction(struct regs *r) {
    uint32_t handler = r->ebx;
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    if (handler != 0 && !rust_signal_handler_addr_ok(handler)) {
        r->eax = (uint32_t)SYS_ERR_INVAL;   /* handler not in the user code window */
        return;
    }
    tasks[cur].sig_handler = handler;
    tasks[cur].in_signal   = 0;
    r->eax = SYS_OK;
}

/* SYS_SIGRETURN is serviced directly in interrupt_handler64 (it must rewrite the
 * live trap frame). This table stub only runs if sigreturn is called outside a
 * handler -- in which case there is nothing to resume, so it fails. */
static void h_sigreturn_stub(struct regs *r) {
    r->eax = (uint32_t)SYS_ERR_INVAL;   /* sigreturn called outside a handler */
}

/* SYS_SIGMASK: block/unblock THIS task's own signals. `ebx` = how (SIG_SETMASK /
 * SIG_BLOCK / SIG_UNBLOCK), `ecx` = mask. A blocked signal that arrives stays in
 * pending_sigs and is delivered once unblocked (see deliver_pending_signal).
 * SIG_KILL can never be blocked. Returns the previous blocked mask. Self-only. */
static void h_sigmask(struct regs *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint32_t how  = r->ebx;
    uint32_t mask = r->ecx;
    uint32_t old  = tasks[cur].sig_mask;
    uint32_t nm;
    if      (how == SIG_BLOCK)   nm = old | mask;
    else if (how == SIG_UNBLOCK) nm = old & ~mask;
    else                         nm = mask;             /* SIG_SETMASK (default) */
    nm &= ~(1u << SIG_KILL);                            /* SIG_KILL is never blockable */
    tasks[cur].sig_mask = nm;
    r->eax = old;
}

/* SYS_SIGALTSTACK (72): register (ss_size != 0) or disable (ss_size == 0) THIS
 * task's own alternate signal stack. When set, a signal delivered while the task
 * is not already running on it enters the handler on [ss_sp, ss_sp+ss_size)
 * instead of the interrupted user stack (see try_deliver_fault_signal in idt.c).
 * Self-only authority — a task sets its own altstack, never another's. The range
 * must lie wholly inside the user address space and be at least SIG_ALTSTACK_MIN
 * bytes, and cannot be changed while a handler is already running on it
 * (SS_ONSTACK) — all three fail closed. Returns SYS_OK or a negative SYS_ERR_*. */
static void h_sigaltstack(struct regs *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint32_t sp   = r->ebx;
    uint32_t size = r->ecx;

    /* Re-pointing the altstack while executing on it would corrupt the running
     * handler's own frame — POSIX returns EPERM here; fail closed. */
    if (tasks[cur].sig_on_stack) { r->eax = (uint32_t)SYS_ERR_PERM; return; }

    if (size == 0) {                                  /* disable */
        tasks[cur].sig_altstack_sp   = 0;
        tasks[cur].sig_altstack_size = 0;
        r->eax = SYS_OK;
        return;
    }
    if (size < SIG_ALTSTACK_MIN)                 { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    if (sp < USER_AREA_BASE)                     { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    if ((uint64_t)sp + (uint64_t)size > USER_MAX_VADDR) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    tasks[cur].sig_altstack_sp   = sp;
    tasks[cur].sig_altstack_size = size;
    r->eax = SYS_OK;
}

typedef struct {
    void   (*fn)(struct regs *r);
    uint16_t slot;     /* authorizing cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;

#define SYSCALL_TABLE_SIZE 76

/* ------------------------------------------------------------------------- *
 *  Capability-checked dispatch table.
 *
 *  Every syscall has exactly one entry. syscall_handler() validates the
 *  number, enforces the declared capability in ONE place, then calls the
 *  handler -- so a syscall physically cannot be reached without its check, and
 *  an unknown / reserved number (or a gap such as 1, 2, 20) fails closed.
 *
 *  slot == SC_NONE means there is no single fixed authorizing capability: the
 *  handler (or the helper it calls) performs its own authorization, noted per
 *  entry. A few entries declare the fixed part here and keep an extra,
 *  argument-dependent check in the handler (block uid==0, register-fs ep slot).
 * ------------------------------------------------------------------------- */
static const syscall_desc_t syscall_table[SYSCALL_TABLE_SIZE] = {
    [0]                            = { h_yield,                   SC_NONE, 0, SC_ANYTYPE },
    [SYS_EXIT]                     = { h_exit,                    SC_NONE, 0, SC_ANYTYPE }, /* self-terminate */
    [SYS_KILL]                     = { h_kill,                    SC_NONE, 0, SC_ANYTYPE }, /* CAP_TCB/admin in handler */
    [SYS_GET_LINE]                 = { h_get_line,                SC_NONE, 0, SC_ANYTYPE }, /* slot 8 or 3 READ (fallback in handler) */
    [4]                            = { h_cap_mint,                SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_mint */
    [5]                            = { h_clear,                   3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [6]                            = { h_sysinfo,                 SC_NONE, 0, SC_ANYTYPE }, /* ambient version string */
    [7]                            = { h_debug_exec,              SC_NONE, 0, SC_ANYTYPE }, /* DEBUG_SHELL only */
    [8]                            = { h_cap_transfer,            SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_transfer */
    [9]                            = { h_cap_move,                SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_move */
    [SYS_SBRK]                     = { h_sbrk,                    SC_NONE, 0, SC_ANYTYPE }, /* own heap, bounds-checked */
    [SYS_WRITE]                    = { h_write,                   SC_NONE, 0, SC_ANYTYPE }, /* ambient console (fd 1) */
    [SYS_READ]                     = { h_read,                    SC_NONE, 0, SC_ANYTYPE }, /* fd 0 ambient; fd>=3 slot-3 READ in handler */
    [SYS_OPEN]                     = { h_open,                    3, CAP_RIGHT_READ, SC_ANYTYPE },
    [14]                           = { h_exec,                    3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [15]                           = { h_ramfs_create,            3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [16]                           = { h_fs_list,                 3, CAP_RIGHT_READ, SC_ANYTYPE },
    [SYS_WAIT]                     = { h_wait,                    SC_NONE, 0, SC_ANYTYPE },
    [SYS_GET_TASK_INFO]            = { h_task_info,               SC_NONE, 0, SC_ANYTYPE }, /* self, or admin/audit in handler */
    [SYS_EXEC]                     = { h_run,                     3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_IPC_SEND]                 = { h_ipc_send,                3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_IPC_RECV]                 = { h_ipc_recv,                3, CAP_RIGHT_READ,  SC_ANYTYPE },
    [SYS_IPC_CALL]                 = { h_ipc_call,                3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_IPC_REPLY]                = { h_ipc_reply,               3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_NOTIFY]                   = { h_notify,                  3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_WAIT_NOTIFY]              = { h_wait_notify,             3, CAP_RIGHT_READ,  SC_ANYTYPE },
    [SYS_RECEIVE_PROGRAM]          = { h_receive_program,         3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_SPAWN]                    = { h_spawn,                   3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_EXEC_NAMED]               = { h_exec_named,              3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_CAP_GRANT]                = { h_cap_grant,               SC_NONE, 0, SC_ANYTYPE }, /* CAP_TCB-to-target/admin in handler */
    [SYS_SIGNAL]                   = { h_signal,                  SC_NONE, 0, SC_ANYTYPE }, /* CAP_TCB-to-target/admin in handler */
    [SYS_SIGMASK]                  = { h_sigmask,                 SC_NONE, 0, SC_ANYTYPE }, /* self: block/unblock own signals */
    [SYS_SPAWN_ARG]                = { h_spawn_arg,               SC_NONE, 0, SC_ANYTYPE }, /* self: read own spawn argument */
    [SYS_GET_ARGV]                 = { h_get_argv,                SC_NONE, 0, SC_ANYTYPE }, /* self: read own argument vector */
    /* execve-from-fd: spawn/exec a caller-supplied program image. Same slot-3
     * WRITE|EXEC gate as SYS_SPAWN / SYS_EXEC_NAMED; the image is validated by the
     * loader (arm_image_from_user -> try_elf_load) exactly like a named binary. */
    [SYS_SPAWN_IMAGE]              = { h_spawn_image,             3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_EXEC_IMAGE]               = { h_exec_image,              3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_SIGALTSTACK]              = { h_sigaltstack,             SC_NONE, 0, SC_ANYTYPE }, /* self: register own altstack */
    /* Zero-trust identity: a receiver reads the kernel-attested uid of an
     * endpoint's last sender. Slot-3 READ (same as SYS_IPC_RECV) so only a
     * legitimate receiver on the endpoint can query it. */
    [SYS_IPC_SENDER]               = { h_ipc_sender,              3, CAP_RIGHT_READ, SC_ANYTYPE },
    /* Object-store owner/mode persistence — same gate as the rest of the store
     * (CAP_BLOCK_DEV slot 7 + uid 0 in the handler): filesystem server only. */
    [SYS_FS_SET_META]              = { h_fs_set_meta,             7, CAP_BLOCK_DEV, SC_ANYTYPE },
    /* Reply routed to the request's kernel-recorded sender (multi-client safe).
     * Slot-3 WRITE, same as the other send/reply paths. */
    [SYS_IPC_REPLY_TO]             = { h_ipc_reply_to,            3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_GETUID]                   = { h_getuid,                  SC_NONE, 0, SC_ANYTYPE },
    [SYS_AUTH]                     = { h_auth,                    SC_NONE, 0, SC_ANYTYPE }, /* self-authorizing */
    [SYS_SUDO]                     = { h_sudo,                    SC_NONE, 0, SC_ANYTYPE }, /* re-auth in handler */
    [SYS_GET_PASS]                 = { h_get_pass,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_USERADD]                  = { h_useradd,                 SC_NONE, 0, SC_ANYTYPE }, /* admin check in do_useradd */
    [SYS_USERDEL]                  = { h_userdel,                 SC_NONE, 0, SC_ANYTYPE }, /* admin check in do_userdel */
    [SYS_PASSWD]                   = { h_passwd,                  SC_NONE, 0, SC_ANYTYPE }, /* admin/self in do_passwd */
    [SYS_ROTATE_KEYS]              = { h_rotate_keys,             8, CAP_RIGHT_READ, CAP_CONSOLE },
    [SYS_READ_AUDIT]               = { h_read_audit,              7, CAP_RIGHT_READ, CAP_AUDIT },
    /* Syscalls 38-45 were the legacy in-memory capfs (a parallel, unencrypted
     * capability-FS separate from the encrypted fs_server). Removed: the entries
     * are absent, so the dispatcher fails them closed (SYS_ERR_NOSYS). The
     * numbers are left reserved (not reused) so no future syscall silently
     * inherits an old ring-3 caller. */
    [SYS_REGISTER_STORAGE_BACKEND] = { h_register_storage_backend, SC_NONE, 0, SC_ANYTYPE },
    [SYS_BLOCK_READ]               = { h_block_read,              7, CAP_BLOCK_DEV, SC_ANYTYPE }, /* + uid 0 in handler */
    [SYS_BLOCK_WRITE]              = { h_block_write,             7, CAP_BLOCK_DEV, SC_ANYTYPE }, /* + uid 0 in handler */
    [SYS_REGISTER_FS_SERVER]       = { h_register_fs_server,      6, CAP_RIGHT_ALL, CAP_USER }, /* + ep lookup in handler */
    [SYS_CONNECT_FS_SERVER]        = { h_connect_fs_server,       SC_NONE, 0, SC_ANYTYPE },
    [SYS_CAP_REVOKE]               = { h_cap_revoke,              SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_revoke */
    [SYS_AUDIT_DIGEST]             = { h_audit_digest,            7, CAP_RIGHT_READ, CAP_AUDIT },
#ifdef PREEMPT_SELFTEST
    /* Test-only trace hook; absent (fails closed) in the ship kernel. */
    [SYS_PREEMPT_TRACE]            = { h_preempt_trace,           SC_NONE, 0, SC_ANYTYPE },
#endif
    [SYS_SIGACTION]                = { h_sigaction,               SC_NONE, 0, SC_ANYTYPE }, /* self: register own handler */
    [SYS_SIGRETURN]                = { h_sigreturn_stub,          SC_NONE, 0, SC_ANYTYPE }, /* real work in interrupt_handler64 */
    /* Encrypted object-store API — same gate as the raw block syscalls
     * (CAP_BLOCK_DEV slot 7 here + uid 0 in the handler). */
    [SYS_FS_INODE_ALLOC]           = { h_fs_inode_alloc,          7, CAP_BLOCK_DEV, SC_ANYTYPE },
    [SYS_FS_INODE_FREE]            = { h_fs_inode_free,           7, CAP_BLOCK_DEV, SC_ANYTYPE },
    [SYS_FBLOCK_READ]              = { h_fblock_read,             7, CAP_BLOCK_DEV, SC_ANYTYPE },
    [SYS_FBLOCK_WRITE]             = { h_fblock_write,            7, CAP_BLOCK_DEV, SC_ANYTYPE },
    [SYS_FS_STAT]                  = { h_fs_stat,                 7, CAP_BLOCK_DEV, SC_ANYTYPE },
    [SYS_FS_SET_SIZE]              = { h_fs_set_size,            7, CAP_BLOCK_DEV, SC_ANYTYPE },
    [SYS_BRK]                     = { h_brk,                    SC_NONE, 0, SC_ANYTYPE }, /* own heap, demand-paged */
};

/* Compile-time guard: the table must have a slot for every syscall number, so
 * no defined syscall can index past it and fall through the
 * `num < SYSCALL_TABLE_SIZE` bound into the deny path by accident.
 * SYS_IPC_REPLY_TO is currently the highest syscall number. Adding a higher one
 * (or shrinking the table) breaks the build here and forces you to grow
 * SYSCALL_TABLE_SIZE -- which lands you right next to the entries you must
 * fill in. (C cannot check the function pointer itself in a static assert; a
 * still-missing entry stays NULL and fails closed at runtime, and adding an
 * entry past the array bound is already a hard compiler error.) */
_Static_assert(SYSCALL_TABLE_SIZE == SYS_IPC_REPLY_TO + 1,
               "syscall_table size must equal (highest syscall number + 1): "
               "grow SYSCALL_TABLE_SIZE and add the new entry when adding a syscall");

void syscall_handler(struct regs *r) {
    if (get_current_task() < MAX_TASKS) {
        tasks[get_current_task()].in_kernel = 1;
    }

    uint32_t num = r->eax;
    const syscall_desc_t *d = (num < SYSCALL_TABLE_SIZE) ? &syscall_table[num] : (const syscall_desc_t *)0;

    if (!d || !d->fn) {
        /* Unknown, reserved, or unimplemented syscall number: fail closed. */
        r->eax = (uint32_t)SYS_ERR_NOSYS;
    } else if (d->slot != SC_NONE) {
        /* Central capability gate: a syscall cannot run without its declared
         * capability. Handlers no longer repeat this check. */
        struct capability *c = cap_lookup(d->slot, d->rights);
        if (!c || (d->ctype != SC_ANYTYPE && (int)c->type != d->ctype)) {
            r->eax = (uint32_t)SYS_ERR_PERM;
        } else {
            d->fn(r);
        }
    } else {
        d->fn(r);
    }

    if (get_current_task() < MAX_TASKS) {
        tasks[get_current_task()].in_kernel = 0;
    }
}


