/* syscall_ipc.c -- synchronous IPC (send/recv/reply over endpoints) plus
 * asynchronous notifications, and their syscall handlers. Split out of
 * syscall.c. */
#include "syscall_internal.h"

#define IPC_SPIN_LIMIT 200000

/* Serialise endpoint + notification operations across CPUs. A raw test-and-set
 * (endpoint_lock) is used because these run inside the int-0x80 handler with IF
 * already clear. In the single-CPU default build these compile to nothing, so
 * that path is byte-for-byte unchanged. The lock guards the mailbox flags, the
 * badge accumulator, and the wake handoff (state -> RUNNABLE + saved-frame
 * patch); the actual task switch onto the woken task is done later by the
 * running-CPU-guarded scheduler.
 *
 * Concurrent-IPC publish order (with ipc_block_switch):
 *   syscall handler sets pending_block only (not yet wake-visible);
 *   ipc_block_switch writes saved_ksp, barriers, then ipc_publish_pending_block
 *   publishes blocked_waiter / WAIT link under this lock. Wakers always patch a
 *   valid frame. */
#ifdef SMP
extern spinlock_t endpoint_lock;
static inline void ipc_lock(void) {
    while (__sync_lock_test_and_set(&endpoint_lock.locked, 1))
        while (endpoint_lock.locked) __asm__ volatile ("pause");
}
static inline void ipc_unlock(void) { __sync_lock_release(&endpoint_lock.locked); }
#else
static inline void ipc_lock(void) { }
static inline void ipc_unlock(void) { }
#endif

/* After tasks[cur].saved_ksp is published: turn pending_block into a real
 * wake-visible wait, or complete immediately if the event already arrived
 * (reply in mailbox / target already dead / badge pending). Returns 1 if the
 * task is now blocked (caller should switch away), 0 to resume the same frame. */
int ipc_publish_pending_block(int cur) {
    if (cur <= 0 || cur >= MAX_TASKS) return 0;
    uint32_t kind = tasks[cur].pending_block;
    tasks[cur].pending_block = 0;
    if (kind == 0) return 0;

    struct interrupt_frame64 *f =
        (struct interrupt_frame64 *)tasks[cur].saved_ksp;
    if (!f) {
        /* No frame: refuse to publish a waiter (would be a use-after-stale). */
        tasks[cur].state        = TASK_RUNNABLE;
        tasks[cur].runnable_ctx = 1;
        return 0;
    }

    if (kind == TASK_BLOCKED_IPC) {
        int reply_ep = tasks[cur].blocked_on;
        if (reply_ep < 0 || reply_ep >= MAX_ENDPOINTS) {
            tasks[cur].state = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            return 0;
        }
        ipc_lock();
        struct endpoint *e = &endpoints[reply_ep];
        /* Reply raced in as a mailbox message before we published the waiter. */
        if (e->has_message) {
            int len = e->msg_len;
            if (len < 0) len = 0;
            if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;
            if (len > 0 && tasks[cur].ipc_reply_buf != 0) {
                copy_to_user((void *)(addr_t)tasks[cur].ipc_reply_buf, e->msg,
                             (size_t)len);
            }
            e->has_message = 0;
            e->last_sender = e->sender_task;
            f->rax = (uint64_t)(uint32_t)len;
            tasks[cur].state        = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            tasks[cur].blocked_on   = -1;
            ipc_unlock();
            return 0;   /* resume same task with reply in hand */
        }
        e->blocked_waiter       = cur;
        tasks[cur].state        = TASK_BLOCKED_IPC;
        tasks[cur].runnable_ctx = 0;
        __asm__ volatile ("" ::: "memory");
        ipc_unlock();
        return 1;
    }

    if (kind == TASK_BLOCKED_WAIT) {
        int tid = tasks[cur].blocked_on;
        /* Re-check: target may have exited after the handler looked. */
        if (tid < 0 || tid >= MAX_TASKS || tasks[tid].state == TASK_DEAD) {
            f->rax = 0;
            tasks[cur].state        = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            tasks[cur].blocked_on   = -1;
            return 0;
        }
        tasks[tid].waiter       = cur;
        tasks[cur].state        = TASK_BLOCKED_WAIT;
        tasks[cur].runnable_ctx = 0;
        __asm__ volatile ("" ::: "memory");
        return 1;
    }

    if (kind == TASK_BLOCKED_NOTIF) {
        int slot = tasks[cur].blocked_on_notif;
        if (slot < 0 || slot >= MAX_NOTIFICATIONS) {
            tasks[cur].state = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            return 0;
        }
        ipc_lock();
        struct notification *n = &notifications[slot];
        if (n->pending_badge != 0) {
            uint32_t b = n->pending_badge;
            n->pending_badge = 0;
            f->rax = 0;
            f->rbx = (uint64_t)b;
            tasks[cur].state        = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            ipc_unlock();
            return 0;
        }
        n->blocked_waiter       = cur;
        tasks[cur].state        = TASK_BLOCKED_NOTIF;
        tasks[cur].runnable_ctx = 0;
        __asm__ volatile ("" ::: "memory");
        ipc_unlock();
        return 1;
    }

    tasks[cur].state        = TASK_RUNNABLE;
    tasks[cur].runnable_ctx = 1;
    return 0;
}

/* Undo a published block when the scheduler cannot switch away (no other
 * runnable task). Clears waiter links so we do not leave a dangling publish. */
void ipc_unpublish_block(int cur) {
    if (cur <= 0 || cur >= MAX_TASKS) return;
    int st = (int)tasks[cur].state;
    if (st == TASK_BLOCKED_IPC) {
        int ep = tasks[cur].blocked_on;
        ipc_lock();
        if (ep >= 0 && ep < MAX_ENDPOINTS && endpoints[ep].blocked_waiter == cur)
            endpoints[ep].blocked_waiter = -1;
        ipc_unlock();
        tasks[cur].blocked_on = -1;
    } else if (st == TASK_BLOCKED_WAIT) {
        int tid = tasks[cur].blocked_on;
        if (tid >= 0 && tid < MAX_TASKS && tasks[tid].waiter == cur)
            tasks[tid].waiter = -1;
        tasks[cur].blocked_on = -1;
    } else if (st == TASK_BLOCKED_NOTIF) {
        int slot = tasks[cur].blocked_on_notif;
        ipc_lock();
        if (slot >= 0 && slot < MAX_NOTIFICATIONS &&
            notifications[slot].blocked_waiter == cur)
            notifications[slot].blocked_waiter = -1;
        ipc_unlock();
    }
    tasks[cur].state        = TASK_RUNNABLE;
    tasks[cur].runnable_ctx = 1;
}

int sys_ipc_send(uint32_t ep, const void *msg, size_t len) {
    if (ep >= MAX_ENDPOINTS) return -1;
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;
    struct endpoint *e = &endpoints[ep];

    /* Snapshot the authorizing write capability (slot 3) so we can confirm it
     * still holds the same identity after the yield loop below. Strictly
     * additive: if the caller has no such cap at entry we don't newly reject
     * (preserves the in-kernel shell caller); we only abort a send whose
     * authorizing cap was revoked/replaced mid-spin (lookup/use TOCTOU). */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_WRITE));

    /* If a task is blocking in SYS_IPC_CALL waiting for a reply on this
     * endpoint, deliver directly: copy from the sender's userspace into a
     * kernel buffer, switch to the waiter's address space, copy into its reply
     * buffer, patch its saved trap frame's rax with the length, then mark it
     * runnable.  ipc_block_switch in interrupt_handler64 already saved the
     * waiter's frame — the next timer tick will iretq it back to ring 3 with
     * the return value in eax. */
    ipc_lock();
    int waiter = e->blocked_waiter;
    if (waiter > 0 && waiter < MAX_TASKS &&
            tasks[waiter].state == TASK_BLOCKED_IPC) {
        if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) { ipc_unlock(); return -1; }

        uint8_t kbuf[IPC_MSG_MAX];
        int copy_len = 0;
        if (len > 0) {
            if (copy_from_user(kbuf, msg, len) != 0) { ipc_unlock(); return -1; }
            copy_len = (int)len;
        }

        if (copy_len > 0 && tasks[waiter].ipc_reply_buf != 0) {
            /* Deliver into the waiter's reply buffer. copy_to_user/user_copy
             * translates the destination through tasks[get_current_task()].cr3,
             * so the *current task* must be the waiter for its buffer to resolve
             * -- merely switching cr3 is not enough (user_copy re-derives and
             * restores cr3 itself). This was the bug: the reply was walked
             * through the sender's page tables and written into the sender's
             * address space, so a SYS_IPC_CALL caller (the shell) only ever saw a
             * zeroed reply. Interrupts are masked so a timer tick cannot observe
             * the transient current-task. */
            uint64_t fl;
            __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
            int sender = get_current_task();
            set_current_task(waiter);
            copy_to_user((void *)(addr_t)tasks[waiter].ipc_reply_buf, kbuf,
                         (size_t)copy_len);
            set_current_task(sender);
            __asm__ volatile ("push %0; popfq" :: "r"(fl) : "memory", "cc");
        }

        /* Patch the waiter's saved interrupt frame so that when the timer
         * resumes it, eax holds the reply length (the return value of
         * sys_ipc_call). saved_ksp is always valid when blocked_waiter is set
         * (publish-after-save); refuse if not. */
        struct interrupt_frame64 *wf =
            (struct interrupt_frame64 *)tasks[waiter].saved_ksp;
        if (!wf) { ipc_unlock(); return -1; }
        wf->rax = (uint64_t)(uint32_t)copy_len;

        e->blocked_waiter = -1;
        __asm__ volatile ("" ::: "memory");
        tasks[waiter].state        = TASK_RUNNABLE;
        tasks[waiter].runnable_ctx = 1;
        tasks[waiter].blocked_on   = -1;
        ipc_unlock();
        return 0;
    }

    /* Non-blocking: if the single mailbox slot is still full, tell the caller to
     * retry. The old form spun in-kernel calling yield(), but the cooperative
     * scheduler cannot correctly switch two ring-3 tasks (only timer preemption
     * can); a caller that polls from ring 3 gets preempted and makes progress. */
    if (e->has_message) { ipc_unlock(); return -2; }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) { ipc_unlock(); return -1; }

    if (len > 0 && copy_from_user(e->msg, msg, len) != 0) { ipc_unlock(); return -1; }
    e->msg_len = (int)len;
    e->sender_task = get_current_task();
    __asm__ volatile ("" ::: "memory");
    e->has_message = 1;
    ipc_unlock();
    return 0;
}

int sys_ipc_recv(uint32_t ep, void *msg, size_t max_len) {
    if (ep >= MAX_ENDPOINTS) return -1;
    struct endpoint *e = &endpoints[ep];

    /* See sys_ipc_send: snapshot the authorizing read capability and revalidate
     * it after the yield loop so a revoke mid-spin aborts the receive. */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_READ));

    /* Non-blocking (see sys_ipc_send): no message yet -> caller polls from ring
     * 3 and is timer-preempted, rather than spinning on the broken cooperative
     * yield in-kernel. */
    ipc_lock();
    if (!e->has_message) { ipc_unlock(); return -2; }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_READ, &auth)) { ipc_unlock(); return -1; }

    int len = e->msg_len;
    if (len > (int)max_len) len = (int)max_len;
    if (len < 0) len = 0;
    if (len > 0 && copy_to_user(msg, e->msg, (size_t)len) != 0) { ipc_unlock(); return -1; }

    e->last_sender = e->sender_task;
    __asm__ volatile ("" ::: "memory");
    e->has_message = 0;
    ipc_unlock();
    return len;
}

int sys_ipc_reply(uint32_t ep, const void *msg, size_t len) {

    return sys_ipc_send(ep, msg, len);
}
/* Notification objects — one 32-bit badge accumulator per slot, plus a
 * blocked-waiter field mirroring the endpoint design. */
struct notification notifications[MAX_NOTIFICATIONS];

/* sys_notify: OR `badge` into the pending_badge of notification `notif_slot`.
 * If a task is currently blocking in SYS_WAIT_NOTIFY on this slot, wake it:
 * deliver the accumulated badge via its saved trap frame (rbx), patch its
 * return value (rax=0), and mark it runnable.  The badge is delivered through
 * the saved interrupt frame so no cross-address-space pointer copy is needed.
 *
 * Multiple notify() calls before a wait() accumulate badges via OR. */
int sys_notify(uint32_t notif_slot, uint32_t badge) {
    if (notif_slot >= MAX_NOTIFICATIONS) return -1;
    struct notification *n = &notifications[notif_slot];

    ipc_lock();
    n->pending_badge |= badge;

    int waiter = n->blocked_waiter;
    if (waiter > 0 && waiter < MAX_TASKS &&
            tasks[waiter].state == TASK_BLOCKED_NOTIF) {
        uint32_t b = n->pending_badge;
        n->pending_badge    = 0;
        n->blocked_waiter   = -1;

        /* Patch the waiter's saved trap frame: rax=0 (success), rbx=badge.
         * saved_ksp is valid whenever blocked_waiter is published. */
        struct interrupt_frame64 *wf =
            (struct interrupt_frame64 *)tasks[waiter].saved_ksp;
        if (wf) {
            wf->rax = 0;
            wf->rbx = (uint64_t)b;
        }

        __asm__ volatile ("" ::: "memory");
        tasks[waiter].state        = TASK_RUNNABLE;
        tasks[waiter].runnable_ctx = 1;
    }
    ipc_unlock();
    return 0;
}

/* sys_wait_notify: if a badge is already pending, consume it and return 0
 * (badge written via r->ebx → frame->rbx by interrupt_handler64).  Otherwise
 * record a pending block; ipc_block_switch saves the frame then publishes the
 * notif waiter so a concurrent sys_notify cannot race a null saved_ksp. */
int sys_wait_notify(uint32_t notif_slot, uint32_t *out_badge) {
    if (notif_slot >= MAX_NOTIFICATIONS) return -1;
    struct notification *n = &notifications[notif_slot];

    ipc_lock();
    if (n->pending_badge != 0) {
        *out_badge = n->pending_badge;
        n->pending_badge = 0;
        ipc_unlock();
        return 0;
    }

    /* No badge pending — intent only; not wake-visible until publish. */
    int cur = get_current_task();
    tasks[cur].blocked_on_notif = (int)notif_slot;
    tasks[cur].pending_block    = TASK_BLOCKED_NOTIF;
    /* out_badge and r->ebx will be patched by sys_notify when it wakes us. */
    *out_badge = 0;
    ipc_unlock();
    return 0;
}


void h_ipc_send(struct regs *r) {
    r->eax = sys_ipc_send(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
}

/* SYS_IPC_CALL (23): atomic send-then-block-until-reply.
 *   ebx = send endpoint index
 *   ecx = reply endpoint index
 *   edx = userspace ptr to message to send
 *   esi = send length
 *   edi = userspace ptr to reply buffer
 * The handler deposits the message and records a pending block only — the
 * reply endpoint's blocked_waiter is *not* published here. interrupt_handler64
 * calls ipc_block_switch, which saves the trap frame first and only then
 * publishes the waiter (so a cross-CPU reply cannot race a null saved_ksp). */
void h_ipc_call(struct regs *r) {
    uint32_t send_ep  = r->ebx;
    uint32_t reply_ep = r->ecx;
    const void *msg   = (const void *)(addr_t)r->edx;
    size_t   send_len = (size_t)r->esi;
    uint32_t reply_buf = r->edi;

    if (send_ep >= MAX_ENDPOINTS || reply_ep >= MAX_ENDPOINTS) {
        r->eax = (uint32_t)-1; return;
    }

    /* Deposit the outgoing message into send_ep. */
    int rc = sys_ipc_send(send_ep, msg, send_len);
    if (rc < 0) { r->eax = (uint32_t)rc; return; }

    int cur = get_current_task();

    /* Intent only — not wake-visible until ipc_publish_pending_block. */
    tasks[cur].ipc_reply_buf = reply_buf;
    tasks[cur].blocked_on    = (int)reply_ep;
    tasks[cur].pending_block = TASK_BLOCKED_IPC;
    /* r->eax is set by interrupt_handler64 after we return; a wake patches
     * saved_ksp->rax with the reply length. */
    r->eax = 0;
}
/* SYS_IPC_RECV (22): slot-3 READ enforced by the table. */
void h_ipc_recv(struct regs *r) {
    r->eax = sys_ipc_recv(r->ebx, (void*)(addr_t)r->ecx, r->edx);
}
/* SYS_IPC_REPLY (24): slot-3 WRITE enforced by the table. */
void h_ipc_reply(struct regs *r) {
    r->eax = sys_ipc_reply(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
}

/* SYS_IPC_SENDER (73): return the authenticated uid of the task that sent the
 * message most recently received on endpoint `ebx`, writing its gid to *ecx.
 * This is the zero-trust identity anchor for a server (e.g. the fs_server): the
 * value is tasks[last_sender].uid — established only by a successful login
 * (SYS_AUTH) and recorded by the kernel when the message was sent — NOT anything
 * the client placed in the message, so a client cannot claim to be another user.
 * Returns (uint32_t)-1 when there is no valid last sender (none yet, or it has
 * since exited). Slot-3 READ is enforced by the dispatch table, so only a task
 * that can legitimately receive on the endpoint may query its sender. */
void h_ipc_sender(struct regs *r) {
    uint32_t ep = r->ebx;
    if (ep >= MAX_ENDPOINTS) { r->eax = (uint32_t)-1; return; }
    int t = endpoints[ep].last_sender;
    if (t <= 0 || t >= MAX_TASKS || tasks[t].state == 0) { r->eax = (uint32_t)-1; return; }
    if (r->ecx) {
        uint32_t g = tasks[t].gid;
        if (copy_to_user((void *)(addr_t)r->ecx, &g, sizeof(g)) != 0) { r->eax = (uint32_t)-1; return; }
    }
    r->eax = tasks[t].uid;
}

/* SYS_IPC_REPLY_TO (75): reply to the task that sent the request most recently
 * received on `req_ep` (ebx), delivering msg (ecx, len edx) DIRECTLY into that
 * task's blocked SYS_IPC_CALL reply buffer — routed by the kernel-recorded sender
 * (endpoints[req_ep].last_sender), never through a shared reply endpoint. This is
 * what makes a single server safe for concurrent clients: two clients cannot
 * collide on one reply endpoint's single blocked_waiter, and a client cannot
 * intercept another's reply (it can't be another request's last_sender). Slot-3
 * WRITE is enforced by the table (same as reply/send).
 *
 * Return: 0 on delivery, or when the sender is gone (nothing to deliver — dropped).
 * A negative value asks the caller (the server's reply loop) to retry: on SMP the
 * sender may have deposited its request but not yet published its block, so it is
 * momentarily not TASK_BLOCKED_IPC; it will be, so retry. On a single CPU the
 * sender is always already blocked by the time the server runs, so no retry
 * occurs. Mirrors the blocked-waiter delivery in sys_ipc_send. */
void h_ipc_reply_to(struct regs *r) {
    uint32_t req_ep = r->ebx;
    const void *msg = (const void *)(addr_t)r->ecx;
    size_t len      = (size_t)r->edx;
    if (req_ep >= MAX_ENDPOINTS) { r->eax = (uint32_t)-1; return; }
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;

    int t = endpoints[req_ep].last_sender;
    if (t <= 0 || t >= MAX_TASKS || tasks[t].state == TASK_DEAD || tasks[t].state == 0) {
        r->eax = 0; return;   /* client gone: nothing to reply to */
    }

    ipc_lock();
    if (tasks[t].state != TASK_BLOCKED_IPC) {
        /* Not blocked yet: racing publish (SMP) -> retry; otherwise not waiting
         * on us (already replied / never called) -> drop. */
        uint32_t racing = (tasks[t].pending_block == (uint32_t)TASK_BLOCKED_IPC);
        ipc_unlock();
        r->eax = racing ? (uint32_t)-2 : 0;
        return;
    }

    uint8_t kbuf[IPC_MSG_MAX];
    int copy_len = 0;
    if (len > 0) {
        if (copy_from_user(kbuf, msg, len) != 0) { ipc_unlock(); r->eax = (uint32_t)-1; return; }
        copy_len = (int)len;
    }

    if (copy_len > 0 && tasks[t].ipc_reply_buf != 0) {
        /* Deliver into the waiter's reply buffer, which resolves through the
         * waiter's CR3 — so make it the current task across the copy (see the
         * identical dance in sys_ipc_send). Interrupts masked so a tick can't
         * observe the transient current-task. */
        uint64_t fl;
        __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
        int sender = get_current_task();
        set_current_task(t);
        copy_to_user((void *)(addr_t)tasks[t].ipc_reply_buf, kbuf, (size_t)copy_len);
        set_current_task(sender);
        __asm__ volatile ("push %0; popfq" :: "r"(fl) : "memory", "cc");
    }

    struct interrupt_frame64 *wf = (struct interrupt_frame64 *)tasks[t].saved_ksp;
    if (!wf) { ipc_unlock(); r->eax = (uint32_t)-1; return; }
    wf->rax = (uint64_t)(uint32_t)copy_len;

    /* Clear the now-stale waiter publication on the client's own reply endpoint
     * (only if it still points to this task; a concurrent client may have
     * overwritten it — harmless, as delivery routed by identity, not by it). */
    int rep = tasks[t].blocked_on;
    if (rep >= 0 && rep < MAX_ENDPOINTS && endpoints[rep].blocked_waiter == t)
        endpoints[rep].blocked_waiter = -1;
    tasks[t].blocked_on = -1;
    __asm__ volatile ("" ::: "memory");
    tasks[t].state        = TASK_RUNNABLE;
    tasks[t].runnable_ctx = 1;
    ipc_unlock();
    r->eax = 0;
}

/* SYS_NOTIFY (25): slot-3 WRITE enforced by the table. */
void h_notify(struct regs *r) {
    r->eax = sys_notify(r->ebx, r->ecx);
}
/* SYS_WAIT_NOTIFY (26): slot-3 READ enforced by the table.
 * The badge is returned in r->ebx so interrupt_handler64 writes it into
 * frame->rbx; the userspace wrapper reads it from the ebx output constraint.
 * For the blocking path r->ebx is patched in sys_notify via saved_ksp->rbx. */
void h_wait_notify(struct regs *r) {
    uint32_t badge = 0;
    r->eax = sys_wait_notify(r->ebx, &badge);
    r->ebx = badge;
}

/* SYS_IRQ_REGISTER (76): bind hardware IRQ ebx to notification slot ecx. The
 * authorizing slot varies per driver, so the table cannot express a fixed gate;
 * we enforce here that the caller holds a CAP_IRQ naming exactly this line. */
void h_irq_register(struct regs *r) {
    int irq = (int)r->ebx;
    if (irq < 0 || irq >= 16 || !caller_holds_irq_cap(irq)) { r->eax = (uint32_t)-1; return; }
    r->eax = (uint32_t)irq_bridge_register(irq, r->ecx, get_current_task());
}

/* SYS_IRQ_ACK (77): re-unmask IRQ ebx after servicing the device. Same
 * CAP_IRQ-naming-the-line gate as SYS_IRQ_REGISTER. */
void h_irq_ack(struct regs *r) {
    int irq = (int)r->ebx;
    if (irq < 0 || irq >= 16 || !caller_holds_irq_cap(irq)) { r->eax = (uint32_t)-1; return; }
    r->eax = (uint32_t)irq_bridge_ack(irq);
}

/* user management (33/34/35): admin/self check lives in do_useradd/userdel/passwd. */

