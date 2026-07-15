#include "kernel.h"

/*
 * storaged — the in-kernel storage service coroutine (STORAGE_RING3_DISK builds).
 *
 * Background: when the block backend is a ring-3 disk_server, the kernel's storage
 * stack (crypto + the crash-atomic redo journal + mount/fsck) must be able to
 * BLOCK on that ring-3 server. But those code paths are synchronous multi-block
 * loops, and Horus's scheduler can only suspend/resume a task at a trap-frame
 * (syscall) boundary — never mid-kernel-call. So the storage stack cannot itself
 * block on disk_server with the existing machinery.
 *
 * Rather than teach the trap-frame scheduler a second (kernel-context) resume path
 * — invasive, and it would touch every hot scheduling path — storaged is a KERNEL
 * COROUTINE with its own stack. Syscall handlers (and the boot mount trigger) run
 * the storage op *on storaged's stack* via kswitch(); when the op needs a sector
 * from disk_server, storaged yields back to its activator, which lets the ordinary
 * ring-3 tasks (fs_server as the blocked caller, disk_server as the driver) run
 * with the ordinary trap-frame blocking. disk_server's completion re-activates
 * storaged, which resumes exactly where it yielded — mid-call — because kswitch
 * saved its whole kernel-execution context (callee-saved regs + rsp) on its stack.
 *
 * This confines the one new "resume a saved kernel context" primitive to a single
 * auditable place (kswitch, below) and leaves the scheduler untouched. storaged
 * runs single-threaded, which also serialises the storage stack.
 *
 * Everything here is compiled only under STORAGE_RING3_DISK; the default (in-kernel
 * ata.c) build never links this file.
 */

/* The coroutine core compiles for the real feature OR the standalone Phase-1
 * coroutine self-test; the ring-3 block backend + protocol below are the feature
 * only (STORAGE_RING3_DISK). */
#if defined(STORAGE_RING3_DISK) || defined(STORAGED_SELFTEST)

/*
 * kswitch(uint64_t *save_old_rsp, uint64_t new_rsp)
 *
 * xv6-style cooperative context switch between two kernel stacks. Saves the
 * callee-saved registers of the *current* context onto its stack, stores the
 * resulting rsp into *save_old_rsp, loads new_rsp, restores the callee-saved
 * registers the mirror switch had pushed, and ret's — resuming the other context
 * exactly where its own kswitch() call left off. SysV: rdi=save_old_rsp, rsi=new_rsp.
 *
 * Only callee-saved state is switched because kswitch is a normal C call: the
 * compiler has already spilled any live caller-saved registers around it.
 */
__asm__(
    ".text\n"
    ".global kswitch\n"
    "kswitch:\n"
    "    pushq %rbp\n"
    "    pushq %rbx\n"
    "    pushq %r12\n"
    "    pushq %r13\n"
    "    pushq %r14\n"
    "    pushq %r15\n"
    "    movq %rsp, (%rdi)\n"   /* *save_old_rsp = current rsp */
    "    movq %rsi, %rsp\n"     /* switch to the target stack   */
    "    popq %r15\n"
    "    popq %r14\n"
    "    popq %r13\n"
    "    popq %r12\n"
    "    popq %rbx\n"
    "    popq %rbp\n"
    "    ret\n"
);
extern void kswitch(uint64_t *save_old_rsp, uint64_t new_rsp);

/* storaged runs on its own kernel stack (shared kernel mapping, present in every
 * address space, so an op can run under whatever cr3 the activator had). Sized
 * generously: the full crypto+journal+fsck call chain plus any ring-0 ISR frames
 * that land while storaged is the current stack run here. */
#define STORAGED_STACK_SIZE 32768
static uint8_t storaged_stack[STORAGED_STACK_SIZE] __attribute__((aligned(16)));

static uint64_t g_storaged_rsp;    /* saved rsp: where to resume storaged        */
static uint64_t g_activator_rsp;   /* saved rsp: where storaged returns on yield  */
static int      g_storaged_ready;  /* bootstrap done                              */

static void storaged_main(void);

/*
 * Yield from storaged back to whoever activated it. Called from deep inside a
 * storage op (via the ring-3 block backend) when it must wait for disk_server, and
 * from the top of the loop when there is no work. Resumes here on the next
 * storaged_activate(), with the entire mid-op stack intact.
 */
void storaged_yield(void) {
    kswitch(&g_storaged_rsp, g_activator_rsp);
}

/*
 * Run storaged until its next yield. Called from a kernel context (a storage
 * syscall handler, disk_server's completion handler, or the boot mount trigger)
 * that has already published whatever storaged needs to make progress. Returns
 * once storaged yields — either because its op now needs disk I/O, or because it
 * has gone idle.
 */
void storaged_activate(void) {
    if (!g_storaged_ready) return;
    kswitch(&g_activator_rsp, g_storaged_rsp);
}

/*
 * One-time bootstrap: craft storaged's stack so the first kswitch into it ret's
 * into storaged_main() with a clean (garbage-but-unused) callee-saved frame.
 */
void storaged_bootstrap(void) {
    uint64_t *sp = (uint64_t *)((uintptr_t)(storaged_stack + STORAGED_STACK_SIZE) & ~0xFULL);
    *--sp = (uint64_t)storaged_main;   /* the first `ret` lands in storaged_main */
    sp -= 6;                            /* r15,r14,r13,r12,rbx,rbp popped on entry */
    g_storaged_rsp   = (uint64_t)sp;
    g_storaged_ready = 1;
}

#ifdef STORAGE_RING3_DISK
/* ---- ring-3 disk_server block backend + protocol ------------------------- *
 * These read/write ops run ONLY on storaged. Each posts a {op,lba} request to the
 * registered disk_server (a notification whose badge carries op+lba), then
 * cooperatively blocks storaged; disk_server does the PIO against its 512-byte
 * bounce buffer and calls SYS_BLKDEV_COMPLETE, which re-activates storaged. Only
 * ciphertext ever crosses into the driver's memory (crypto sits above this seam).
 */
#define BLK_SECTOR   512
#define BLK_OP_READ  0
#define BLK_OP_WRITE 1

static int          g_blk_task     = -1;  /* disk_server task id (-1 = none yet)   */
static uint64_t     g_blk_bounce   = 0;   /* disk_server's 512B bounce buffer vaddr */
static int          g_blk_slot     = -1;  /* notification slot it waits on          */
static volatile int g_blk_result   = 0;   /* set by SYS_BLKDEV_COMPLETE             */
static volatile int g_blk_inflight = 0;   /* a request is posted, awaiting complete */

int blkdev_registered(void) { return g_blk_task > 0; }

/* Copy one sector between a kernel buffer and disk_server's bounce, resolving the
 * bounce vaddr through disk_server's address space (the h_ipc_reply_to idiom:
 * transiently make it the current task, interrupts masked). Returns 0 on success. */
static int blk_bounce_copy(void *kbuf, int to_bounce) {
    if (g_blk_task <= 0 || !g_blk_bounce) return -1;
    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    int saved = get_current_task();
    set_current_task(g_blk_task);
    int rc;
    if (to_bounce) rc = copy_to_user((void *)(uintptr_t)g_blk_bounce, kbuf, BLK_SECTOR);
    else           rc = copy_from_user(kbuf, (void *)(uintptr_t)g_blk_bounce, BLK_SECTOR);
    set_current_task(saved);
    if (fl & 0x200) __asm__ volatile ("sti" ::: "memory");
    return rc;
}

/* One block op — MUST run on storaged. Post {op,lba}, cooperatively block until
 * disk_server completes, then move the sector. Returns 0 ok, <0 on error. */
static int ring3_blk_op(int op, uint64_t lba, void *buf) {
    if (g_blk_task <= 0) return -1;                 /* no driver registered */
    if (lba > 0x7FFFFFFFu) return -1;               /* badge carries a 31-bit lba */
    if (op == BLK_OP_WRITE && blk_bounce_copy(buf, 1) != 0) return -1;

    g_blk_result   = -1;
    g_blk_inflight = 1;
    uint32_t badge = (op == BLK_OP_WRITE ? 0x80000000u : 0u) | (uint32_t)lba;
    sys_notify((uint32_t)g_blk_slot, badge);
    storaged_yield();                                /* disk_server runs; COMPLETE resumes us */

    if (g_blk_result != 0) return g_blk_result;
    if (op == BLK_OP_READ && blk_bounce_copy(buf, 0) != 0) return -1;
    return 0;
}

static int ring3_read_block(block_device_t *bd, uint64_t block, void *buf) {
    (void)bd; return ring3_blk_op(BLK_OP_READ, block, buf);
}
static int ring3_write_block(block_device_t *bd, uint64_t block, const void *buf) {
    (void)bd; return ring3_blk_op(BLK_OP_WRITE, block, (void *)buf);
}
block_device_t g_ring3_bd = {
    .name = "ring3disk",
    .total_blocks = 0,          /* filled in at registration */
    .read_block  = ring3_read_block,
    .write_block = ring3_write_block,
    .private = 0,
};

static void blkdev_on_register(void);   /* phase-specific: kick a test, or mount */

/* SYS_BLKDEV_REGISTER (78): disk_server announces itself as the block backend.
 * ebx=bounce vaddr, ecx=notification slot, edx=total blocks. CAP_BLOCK_DEV gated. */
void h_blkdev_register(struct regs *r) {
    if (!caller_holds_blkdev_cap()) { r->eax = (uint32_t)-1; return; }
    g_blk_task    = get_current_task();
    g_blk_bounce  = (uint64_t)r->ebx;
    g_blk_slot    = (int)r->ecx;
    g_ring3_bd.total_blocks = r->edx ? r->edx : BLOCKS_PER_DISK;
    r->eax = 0;
    blkdev_on_register();
}

/* SYS_BLKDEV_COMPLETE (79): the just-notified request is done; resume storaged.
 * ebx=result (0 ok, <0 I/O error). CAP_BLOCK_DEV gated + must be the driver. */
void h_blkdev_complete(struct regs *r) {
    if (!caller_holds_blkdev_cap() || get_current_task() != g_blk_task) {
        r->eax = (uint32_t)-1; return;
    }
    r->eax = 0;
    if (!g_blk_inflight) return;        /* nothing outstanding — ignore */
    g_blk_result   = (int)r->ebx;
    g_blk_inflight = 0;
    storaged_activate();                /* resume storaged after its yield in ring3_blk_op */
}
#endif /* STORAGE_RING3_DISK */

/* ---- storaged_main: one of three, chosen at build time ------------------- */
#if defined(STORAGED_SELFTEST)
/*
 * Phase-1 proof that kswitch preserves a mid-call kernel stack across a yield.
 * storaged does the first half of an "op", yields (as a real op would when it
 * needs a sector), and on re-activation must resume right after the yield and do
 * the second half — proving its stack (and the local control flow) survived other
 * code running in between.
 */
static volatile int g_st_counter;

static void storaged_main(void) {
    for (;;) {
        g_st_counter += 100;   /* first half of the op */
        storaged_yield();      /* suspend mid-op — must resume on the next line */
        g_st_counter += 23;    /* second half; only correct if the stack survived */
        storaged_yield();      /* op done — go idle until re-activated */
    }
}

void storaged_selftest(void) {
    storaged_bootstrap();

    storaged_activate();                 /* enters storaged_main, runs +100, yields */
    if (g_st_counter != 100) { print("STORAGED_SELFTEST: FAIL half1\n"); return; }

    storaged_activate();                 /* resumes mid-op, runs +23, yields */
    if (g_st_counter != 123) { print("STORAGED_SELFTEST: FAIL resume-mid-op\n"); return; }

    storaged_activate();                 /* loop iter 2: +100 again */
    if (g_st_counter != 223) { print("STORAGED_SELFTEST: FAIL loop\n"); return; }

    print("STORAGED_SELFTEST: PASS coroutine save/restore across yield\n");
}

#elif defined(BLKDEV_SELFTEST)
/*
 * Phase-2 proof of the storaged<->disk_server data path. Kicked once disk_server
 * has registered (from blkdev_on_register): write a known sector via the ring-3
 * backend, read it back, and verify the round-trip. Exercises the full request /
 * cooperative-block / complete / bounce-copy cycle without the storage stack.
 */
static void storaged_main(void) {
    static uint8_t wbuf[BLK_SECTOR];
    static uint8_t rbuf[BLK_SECTOR];
    for (int i = 0; i < BLK_SECTOR; i++) { wbuf[i] = (uint8_t)(i * 13 + 7); rbuf[i] = 0; }

    int w  = ring3_blk_op(BLK_OP_WRITE, 1, wbuf);
    int rd = ring3_blk_op(BLK_OP_READ,  1, rbuf);
    int ok = (w == 0 && rd == 0);
    for (int i = 0; i < BLK_SECTOR && ok; i++) if (rbuf[i] != wbuf[i]) ok = 0;

    print(ok ? "BLKDEV_SELFTEST: PASS storaged<->disk_server sector round-trip\n"
             : "BLKDEV_SELFTEST: FAIL round-trip\n");
    for (;;) storaged_yield();            /* done — park */
}

static void blkdev_on_register(void) {
    storaged_bootstrap();
    storaged_activate();                  /* run the round-trip now that the driver is up */
}

#else  /* STORAGE_RING3_DISK real feature */
/* Real request loop lands here in Phase 3 (dequeue storage request -> run the
 * storage op on this stack -> deliver to the blocked caller). Until then it parks;
 * blkdev_on_register triggers the deferred mount in Phase 3. */
static void storaged_main(void) {
    for (;;) storaged_yield();
}
static void blkdev_on_register(void) {
    /* Phase 3: enqueue the deferred mount job + activate storaged. */
}
#endif

#endif /* STORAGE_RING3_DISK || STORAGED_SELFTEST */
