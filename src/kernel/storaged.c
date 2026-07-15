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

#ifdef STORAGE_RING3_DISK

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

#ifdef STORAGED_SELFTEST
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
#else
/* Real request loop lands here in Phase 2/3 (dequeue -> run storage op -> deliver).
 * Until then storaged just parks; nothing activates it in a non-selftest build. */
static void storaged_main(void) {
    for (;;) storaged_yield();
}
#endif /* STORAGED_SELFTEST */

#endif /* STORAGE_RING3_DISK */
