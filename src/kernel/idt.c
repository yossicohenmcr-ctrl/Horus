#include "kernel.h"

#define PAGE_PRESENT   (1 << 0)
#define RECURSIVE_PD_VADDR  0xFFFFF000
#define RECURSIVE_PT_VADDR  0xFFC00000

typedef uint32_t pde_t;
typedef uint32_t pte_t;

#define PAGE_COW       (1 << 9)

int handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code);

/* Weak stub: the real implementation is in Rust (when linked). Returns -1 so the
 * C demand-pager in page_fault_handler remains the single authoritative call site.
 * Previously this stub called handle_demand_page_fault itself, causing a double
 * invocation: the second call found the page already present (-2), fell through to
 * rust_validate_page_fault, and could kill a task whose fault was already handled. */
__attribute__((weak))
int rust_handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code, bool is_cow, uint16_t ref_count) {
    (void)fault_addr; (void)err_code; (void)is_cow; (void)ref_count;
    return -1;   /* not handled; caller will invoke handle_demand_page_fault once */
}

struct idt_ptr {
    uint16_t limit;
    addr_t   base;
} __attribute__((packed));

struct idt_entry64 {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

static struct idt_entry64 idt64[256] __attribute__((aligned(16)));
static struct idt_ptr idt64_ptr;

void setup_early_idt64(void) { }

char keyboard_buffer[256];
uint32_t kb_head = 0;
uint32_t kb_tail = 0;

static uint8_t ps2_e0_prefix;

static char ps2_translate(uint8_t sc) {
    if (ps2_e0_prefix) {
        ps2_e0_prefix = 0;
        if (sc >= 0x80) return 0; 
        if (sc == 0x53) return 0x7F; 
        
        return 0;
    }
    if (sc == 0xE0) {
        ps2_e0_prefix = 1;
        return 0;
    }
    if (sc >= 0x80) return 0; 

    if (sc == 0x0E) return '\b';
    if (sc == 0x0F) return '\t';
    if (sc == 0x01) return 0x1B; 

    if (sc >= 0x02 && sc <= 0x0B) return "1234567890"[sc-0x02];
    if (sc >= 0x10 && sc <= 0x19) return "qwertyuiop"[sc-0x10];
    if (sc >= 0x1E && sc <= 0x26) return "asdfghjkl"[sc-0x1E];
    if (sc >= 0x2C && sc <= 0x32) return "zxcvbnm"[sc-0x2C];

    if (sc == 0x39) return ' ';
    if (sc == 0x1C) return '\n';

    if (sc == 0x0C) return '-';
    if (sc == 0x0D) return '=';
    if (sc == 0x1A) return '[';
    if (sc == 0x1B) return ']';
    if (sc == 0x2B) return '\\';
    if (sc == 0x27) return ';';
    if (sc == 0x28) return '\'';
    if (sc == 0x29) return '`';
    if (sc == 0x33) return ',';
    if (sc == 0x34) return '.';
    if (sc == 0x35) return '/';

    return 0;
}

extern void isr0(void); extern void isr1(void); extern void isr2(void); extern void isr3(void);
extern void isr4(void); extern void isr5(void); extern void isr6(void); extern void isr7(void);
extern void isr8(void); extern void isr9(void); extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void); extern void isr15(void);
extern void isr16(void); extern void isr17(void); extern void isr18(void); extern void isr19(void);
extern void isr20(void); extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void); extern void isr27(void);
extern void isr28(void); extern void isr29(void); extern void isr30(void); extern void isr31(void);
extern void isr32(void); extern void isr33(void); extern void isr34(void); extern void isr35(void);
extern void isr36(void); extern void isr37(void); extern void isr38(void); extern void isr39(void);
extern void isr40(void); extern void isr41(void); extern void isr42(void); extern void isr43(void);
extern void isr44(void); extern void isr45(void); extern void isr46(void); extern void isr47(void);
extern void isr128(void);

extern tcb_t tasks[MAX_TASKS];

#ifdef SMP
extern void lapic_eoi(void);                    /* scheduler.c */
extern volatile unsigned long ap_timer_ticks;   /* scheduler.c */
extern void smp_ack_shootdown(void);            /* scheduler.c */
#endif

void interrupt_handler(struct regs *r);
/* Returns non-zero kernel %rsp to resume on (task switch), or 0 to keep frame. */
uint64_t page_fault_handler(struct regs *r);

void segfault_park(void);

/* Redirect a ring-3 fault into the task's registered signal handler instead of
 * killing it. Returns 1 if delivered (the caller must return into the handler),
 * 0 to fall through to the normal kill path. Preconditions enforced here:
 *   - the fault came from ring 3 (cs & 3),
 *   - the task is not already inside a handler (in_signal) -- a fault *in* the
 *     handler is NOT redirected, so a faulting handler cannot loop,
 *   - a handler is registered and its address is inside the user code window
 *     (validated in safe Rust; fail closed).
 * On delivery the full pre-signal trap frame is saved for SYS_SIGRETURN, and the
 * live frame is rewritten to enter the handler in ring 3 with the signal number
 * in ebx and the faulting address in ecx. cs/ss are unchanged, so the handler
 * runs at ring 3 -- no new privilege is granted. rsp is the interrupted user
 * stack, UNLESS the task registered an alternate signal stack (SYS_SIGALTSTACK)
 * and is not already running on it, in which case the handler runs on that stack
 * (SS_ONSTACK) so a corrupt or overflowed primary stack cannot stop the handler
 * from running; sigreturn clears the on-stack flag. */
int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                             uint32_t signum, uint64_t fault_addr) {
    if (cur <= 0 || cur >= MAX_TASKS) return 0;
    if ((frame->cs & 3) == 0)         return 0;   /* ring-0 fault: never */
    if (tasks[cur].in_signal)         return 0;   /* fault inside handler -> kill */
    uint32_t h = tasks[cur].sig_handler;
    if (h == 0 || !rust_signal_handler_addr_ok(h)) return 0;

    /* Pick the handler's stack before saving the frame, so sig_frame keeps the
     * interrupted rsp for an exact SYS_SIGRETURN. Align the altstack top to 16
     * bytes minus 8 to reproduce the rsp%16==8 a normal call-entry would give. */
    uint64_t hrsp = frame->rsp;
    if (tasks[cur].sig_altstack_size && !tasks[cur].sig_on_stack) {
        hrsp = ((uint64_t)tasks[cur].sig_altstack_sp +
                (uint64_t)tasks[cur].sig_altstack_size) & ~0xFULL;
        hrsp -= 8;
        tasks[cur].sig_on_stack = 1;
    }

    tasks[cur].sig_frame = *frame;     /* full context for SYS_SIGRETURN */
    tasks[cur].in_signal = 1;

    frame->rip     = (uint64_t)h;
    frame->rsp     = hrsp;                  /* interrupted stack, or the altstack */
    frame->rbx     = (uint64_t)signum;     /* ebx = signal number */
    frame->rcx     = fault_addr;           /* ecx = faulting address (0 if n/a) */
    frame->rflags |= 0x200;                /* ensure IF set while the handler runs */
    return 1;
}

/* ---- IRQ -> notification bridge (ring-3 device drivers) ------------------- *
 * A ring-3 driver binds a hardware IRQ to one of its notification slots via
 * SYS_IRQ_REGISTER. On that line's interrupt the kernel keeps full control of the
 * PIC -- it EOIs immediately, masks the line so it cannot re-fire, and delivers a
 * notification to the driver. The driver services the device through its granted
 * ports (TSS I/O bitmap) and calls SYS_IRQ_ACK to unmask the line again. A driver
 * that never acks stalls only its own line, never the kernel or other drivers.
 * The kernel never runs driver code in ring 0 and never hands out IOPL/EOI. */
struct irq_binding { int task; uint32_t notif_slot; int armed; };
static struct irq_binding irq_table[16];

/* Mask (masked=1) or unmask (masked=0) one PIC line. A slave line (8..15) also
 * needs the master's cascade line (IRQ2) unmasked to reach the CPU. */
static void pic_set_mask(int irq, int masked) {
    uint16_t port = (irq < 8) ? 0x21 : 0xA1;
    uint8_t  bit  = (irq < 8) ? (uint8_t)irq : (uint8_t)(irq - 8);
    uint8_t  v    = inb(port);
    if (masked) v |= (uint8_t)(1u << bit);
    else        v &= (uint8_t)~(1u << bit);
    outb(port, v);
    if (irq >= 8 && !masked) {                  /* keep the cascade open */
        uint8_t m = inb(0x21);
        m &= (uint8_t)~(1u << 2);
        outb(0x21, m);
    }
}

/* SYS_IRQ_REGISTER back end (authorization is enforced by the syscall handler).
 * Records the binding and unmasks the line so delivery can begin. */
int irq_bridge_register(int irq, uint32_t notif_slot, int task) {
    if (irq < 0 || irq >= 16) return -1;
    irq_table[irq].task       = task;
    irq_table[irq].notif_slot = notif_slot;
    irq_table[irq].armed      = 1;
    pic_set_mask(irq, 0);
    return 0;
}

/* SYS_IRQ_ACK back end: re-unmask a line the delivery path masked. */
int irq_bridge_ack(int irq) {
    if (irq < 0 || irq >= 16 || !irq_table[irq].armed) return -1;
    pic_set_mask(irq, 0);
    return 0;
}

uint64_t interrupt_handler64(struct interrupt_frame64 *frame)
{
    uint64_t vector = frame->int_no;
    uint64_t *g = (uint64_t *)frame;
    uint64_t vec2 = (vector == 0x80) ? 0x80 : g[15];

    int cur = get_current_task();
    if ((frame->cs & 3) != 0 && cur > 0 && cur < MAX_TASKS) {
        tasks[cur].eip = (uint32_t)frame->rip;
        tasks[cur].esp = (uint32_t)frame->rsp;
    }

    if (vector == 14) {
        uint64_t pf_rsp = page_fault_handler((struct regs *)frame);
        if (pf_rsp) return pf_rsp;
    } else if (vector == 32) {
        /* Timer (IRQ0). EOI first so the PIC keeps delivering ticks even
         * across a task switch, then let the preemptive scheduler decide
         * whether to switch. preempt_on_tick returns the kernel %rsp to resume
         * on: the current frame (no switch) or the next task's saved frame. */
        outb(0x20, 0x20);
        timer_handler();
        return preempt_on_tick((uint64_t)frame, frame->cs);
    } else if (vector == 33) {
        /* Only consume a scancode when the controller output buffer is full,
         * so a spurious IRQ never re-reads a stale byte. */
        if (inb(0x64) & 1) {
            uint8_t scancode = inb(0x60);
            char c = ps2_translate(scancode);
            if (c) {
                keyboard_buffer[kb_tail] = c;
                kb_tail = (kb_tail + 1) % 256;
                if (kb_tail == kb_head) kb_head = (kb_head + 1) % 256;
            }
        }
        outb(0x20, 0x20);
    } else if (vector >= 34 && vector <= 47 && irq_table[vector - 32].armed) {
        /* A device IRQ bound to a ring-3 driver. Keep the PIC in ring 0: EOI the
         * PIC(s), mask this line so it cannot re-fire until the driver acks, then
         * notify the driver task. No driver code runs here; we only post a wake. */
        int irq = (int)vector - 32;
        if (irq >= 8) outb(0xA0, 0x20);
        outb(0x20, 0x20);
        pic_set_mask(irq, 1);
        sys_notify(irq_table[irq].notif_slot, 1u << irq);
        return (uint64_t)frame;
#ifdef SMP
    } else if (vector == 0x40) {
        /* LAPIC timer: the application processors' preemption tick (the legacy
         * PIC IRQ0 only reaches the BSP). EOI to the local APIC, then let the
         * preemptive scheduler decide whether to switch this CPU's task. */
        lapic_eoi();
        __sync_fetch_and_add(&ap_timer_ticks, 1ul);
        return preempt_on_tick((uint64_t)frame, frame->cs);
    } else if (vector == 0xFB) {
        /* TLB-shootdown IPI: a remote CPU changed a shared mapping. Flush this
         * CPU's TLB (reload CR3 drops all non-global entries) and acknowledge. */
        uint64_t cr3;
        __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
        __asm__ volatile ("mov %0, %%cr3" :: "r"(cr3) : "memory");
        smp_ack_shootdown();
        lapic_eoi();
        return (uint64_t)frame;
#endif
    } else if (vector == 0x80 || vec2 == 0x80) {
        int scur = get_current_task();
        if ((uint32_t)frame->rax == SYS_SIGRETURN && scur > 0 && scur < MAX_TASKS
            && tasks[scur].in_signal) {
            /* Handled here (not via the syscall table) because restoring the
             * pre-signal context means rewriting the live trap frame -- rip,
             * rsp and every register -- which the struct-regs dispatch cannot
             * reach. Exact resume of the interrupted instruction. */
            *frame = tasks[scur].sig_frame;
            tasks[scur].in_signal = 0;
            tasks[scur].sig_on_stack = 0;   /* left the alternate signal stack */
            return (uint64_t)frame;
        }
        struct regs r;
        r.eax = (uint32_t)frame->rax;
        r.ebx = (uint32_t)frame->rbx;
        r.ecx = (uint32_t)frame->rcx;
        r.edx = (uint32_t)frame->rdx;
        r.esi = (uint32_t)frame->rsi;
        r.edi = (uint32_t)frame->rdi;
        r.ebp = (uint32_t)frame->rbp;
        r.esp = (uint32_t)frame->rsp;
        r.eip = (uint32_t)frame->rip;
        r.eflags = (uint32_t)frame->rflags;
        r.int_no = 0x80;
        r.err_code = (uint32_t)frame->err_code;
        r.useresp = (uint32_t)frame->rsp;
        r.cs = (uint32_t)frame->cs;
        r.ds = r.es = r.fs = r.gs = r.ss = 0x30;
        int ipc_caller = get_current_task();
        syscall_handler(&r);
        /* SYS_EXEC_NAMED replaced the caller's image in place and fabricated a
         * fresh ring-3 context for it at the top of its kernel stack — which is
         * the SAME memory as this trap `frame`. Resume that context via the
         * saved-frame path (installs the new CR3 + kernel stack) BEFORE the
         * frame->rax/rbx writes below, which would otherwise clobber it. */
        if (g_exec_reenter_task > 0) {
            int t = g_exec_reenter_task;
            g_exec_reenter_task = -1;
            return exec_reenter_switch(t);
        }
        frame->rax = (uint64_t)r.eax;
        /* SYS_WAIT_NOTIFY returns the badge in ebx so the wrapper can read it
         * from the register without needing a cross-address-space pointer copy. */
        frame->rbx = (uint64_t)r.ebx;
        /* SYS_YIELD: voluntary full-context switch (same path as preemption). */
        if (g_want_yield == ipc_caller) {
            g_want_yield = -1;
            return sched_yield_switch(ipc_caller, (uint64_t)frame);
        }
        /* SYS_IPC_CALL / SYS_WAIT_NOTIFY / SYS_WAIT: handlers set pending_block
         * only. ipc_block_switch saves the frame first, then publishes the
         * waiter so a cross-CPU wake cannot race a null/stale saved_ksp. */
        if (ipc_caller > 0 && ipc_caller < MAX_TASKS) {
            int st = (int)tasks[ipc_caller].state;
            if (tasks[ipc_caller].pending_block != 0 ||
                st == TASK_BLOCKED_IPC || st == TASK_BLOCKED_NOTIF ||
                st == TASK_BLOCKED_WAIT) {
                return ipc_block_switch(ipc_caller, (uint64_t)frame);
            }
            /* SYS_EXIT / SYS_KILL-self: the caller terminated itself. It is dead;
             * do not iretq back into it. Resume the next runnable task via its
             * saved trap frame (the same mechanism the timer uses); if nothing
             * else is runnable, fall back to the kernel reaper on task 0's stack. */
            if (st == 0) {
                uint64_t rsp = task_exit_switch(ipc_caller);
                if (rsp) return rsp;
                frame->rip    = (uint64_t)resume_shell_after_fault;
                frame->cs     = 0x08;
                frame->rflags = 0x202;
                frame->rsp    = tasks[0].kernel_stack_top;
                frame->ss     = 0x10;
                return (uint64_t)frame;
            }
        }
    } else if (vector < 32) {

        if ((frame->cs & 3) != 0 && get_current_task() > 0) {
            int cur = get_current_task();
            uint32_t signum = (vector == 6) ? SIG_ILL : SIG_SEGV; /* #UD vs other */
            if (!try_deliver_fault_signal(frame, cur, signum, 0)) {
                int killed = cur;
                /* Tear the task down — marks it dead AND wakes any SYS_WAIT
                 * waiter (e.g. init supervising the shell) — then resume the
                 * next runnable task via its saved frame, exactly as the
                 * SYS_EXIT path does. The old code raw-set state=0 and spun the
                 * cooperative schedule(), which never woke a blocked waiter, so
                 * a faulting shell left a blocking init asleep forever. */
                task_teardown(killed);
                uint64_t rsp = task_exit_switch(killed);
                if (rsp) return rsp;
                /* Nothing else runnable: fall back to the kernel reaper/idle on
                 * task 0's stack. */
                frame->rip    = (uint64_t)resume_shell_after_fault;
                frame->cs     = 0x08;
                frame->rflags = 0x202;
                frame->rsp    = tasks[0].kernel_stack_top;
                frame->ss     = 0x10;
            }
            /* else: signal delivered -> fall through to `return frame`, and the
             * ISR epilogue iretq's into the handler at ring 3. */
        } else {
            println("64-bit EXCEPTION vector=");
            print_hex64(vector);
            println(" err=");
            print_hex64(frame->err_code);
            println(" RIP=");
            print_hex64(frame->rip);
            println(" CS=");
            print_hex64(frame->cs);
            println("");
            println("KERNEL FATAL EXCEPTION - halting");
            for (;;) { asm volatile("cli; hlt"); }
        }
    } else {
        if (vector >= 40) outb(0xA0, 0x20);
        outb(0x20, 0x20);
    }

    /* Default (non-timer, non-switching) path: resume on the same trap frame,
     * i.e. return exactly into the interrupted context. */
    return (uint64_t)frame;
}

void segfault_park(void) {
    for (;;) {
        asm volatile("sti; hlt");
    }
}

void pic_init(void) {
    outb(0x20, 0x11); outb(0xA0, 0x11);
    outb(0x21, 0x20); outb(0xA1, 0x28);
    outb(0x21, 0x04); outb(0xA1, 0x02);
    outb(0x21, 0x01); outb(0xA1, 0x01);
    outb(0x21, 0xFC);
    outb(0xA1, 0xFF);
}

static void keyboard_init(void) {
    uint8_t status;

    while (inb(0x64) & 2);
    outb(0x64, 0xAD);
    while (inb(0x64) & 2);
    outb(0x64, 0xA7);

    while (inb(0x64) & 1) { inb(0x60); }

    while (inb(0x64) & 2);
    outb(0x64, 0x20);
    status = inb(0x60);

    status |= (1 << 0);
    status &= ~(1 << 1);
    status |= (1 << 6);

    while (inb(0x64) & 2);
    outb(0x64, 0x60);
    outb(0x60, status);

    while (inb(0x64) & 2);
    outb(0x64, 0xAE);

    while (inb(0x64) & 2);
    outb(0x60, 0xF4);

    int got_ack = 0;
    int timeout = 100000;
    while (timeout-- > 0) {
        if (inb(0x64) & 1) {
            uint8_t ack = inb(0x60);
            if (ack == 0xFA) { got_ack = 1; break; }
        }
    }

    while (inb(0x64) & 1) { inb(0x60); }
    (void)got_ack;
}

static void serial_init(void) {
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x80);
    outb(0x3F8, 0x03);
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x03);
    outb(0x3FA, 0xC7);
    outb(0x3FC, 0x0B);

    outb(0x2F9, 0x00);
    outb(0x2FB, 0x80);
    outb(0x2F8, 0x03);
    outb(0x2F9, 0x00);
    outb(0x2FB, 0x03);
    outb(0x2FA, 0xC7);
    outb(0x2FC, 0x0B);
}

/* Program PIT channel 0 for a fixed periodic tick so the preemptive scheduler
 * has a deterministic quantum instead of the undefined power-on reload value.
 * 1193182 Hz / 11932 ~= 100 Hz => a 10 ms time slice. Mode 3 (square wave),
 * lobyte/hibyte access. */
#define PIT_TICK_HZ 100
void pit_init(void) {
    uint32_t divisor = 1193182u / PIT_TICK_HZ;
    if (divisor > 0xFFFF) divisor = 0xFFFF;
    outb(0x43, 0x36);                         /* ch0, lo/hi, mode 3, binary */
    outb(0x40, (uint8_t)(divisor & 0xFF));
    outb(0x40, (uint8_t)((divisor >> 8) & 0xFF));
}

static void idt64_set_gate(uint8_t num, uint64_t handler, uint16_t sel, uint8_t ist, uint8_t type_attr)
{
    idt64[num].offset_low  = handler & 0xFFFF;
    idt64[num].selector    = sel;
    idt64[num].ist         = ist;
    idt64[num].type_attr   = type_attr;
    idt64[num].offset_mid  = (handler >> 16) & 0xFFFF;
    idt64[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
    idt64[num].zero        = 0;
}

void idt_init64(void)
{

    for (int i = 0; i < 256; i++) {
        idt64[i].offset_low = 0;
        idt64[i].selector = 0;
        idt64[i].ist = 0;
        idt64[i].type_attr = 0;
        idt64[i].offset_mid = 0;
        idt64[i].offset_high = 0;
        idt64[i].zero = 0;
    }

    extern void isr0(void);  extern void isr1(void);  extern void isr2(void);  extern void isr3(void);
    extern void isr4(void);  extern void isr5(void);  extern void isr6(void);  extern void isr7(void);
    extern void isr8(void);  extern void isr9(void);  extern void isr10(void); extern void isr11(void);
    extern void isr12(void); extern void isr13(void); extern void isr14(void); extern void isr15(void);
    extern void isr16(void); extern void isr17(void); extern void isr18(void); extern void isr19(void);
    extern void isr20(void); extern void isr21(void); extern void isr22(void); extern void isr23(void);
    extern void isr24(void); extern void isr25(void); extern void isr26(void); extern void isr27(void);
    extern void isr28(void); extern void isr29(void); extern void isr30(void); extern void isr31(void);

    idt64_set_gate(0,  (uint64_t)isr0,  0x08, 0, 0x8E);
    idt64_set_gate(1,  (uint64_t)isr1,  0x08, 0, 0x8E);
    idt64_set_gate(2,  (uint64_t)isr2,  0x08, 2, 0x8E); 
    idt64_set_gate(3,  (uint64_t)isr3,  0x08, 0, 0x8E);
    idt64_set_gate(4,  (uint64_t)isr4,  0x08, 0, 0x8E);
    idt64_set_gate(5,  (uint64_t)isr5,  0x08, 0, 0x8E);
    idt64_set_gate(6,  (uint64_t)isr6,  0x08, 0, 0x8E);
    idt64_set_gate(7,  (uint64_t)isr7,  0x08, 0, 0x8E);
    idt64_set_gate(8,  (uint64_t)isr8,  0x08, 1, 0x8E); 
    idt64_set_gate(9,  (uint64_t)isr9,  0x08, 0, 0x8E);
    idt64_set_gate(10, (uint64_t)isr10, 0x08, 0, 0x8E);
    idt64_set_gate(11, (uint64_t)isr11, 0x08, 0, 0x8E);
    idt64_set_gate(12, (uint64_t)isr12, 0x08, 3, 0x8E); 
    idt64_set_gate(13, (uint64_t)isr13, 0x08, 1, 0x8E); 
    idt64_set_gate(14, (uint64_t)isr14, 0x08, 1, 0x8E); 
    extern void isr128(void);
    idt64_set_gate(0x80, (uint64_t)isr128, 0x08, 0, 0xEE);
    idt64_set_gate(15, (uint64_t)isr15, 0x08, 0, 0x8E);
    idt64_set_gate(16, (uint64_t)isr16, 0x08, 0, 0x8E);
    idt64_set_gate(17, (uint64_t)isr17, 0x08, 0, 0x8E);
    idt64_set_gate(18, (uint64_t)isr18, 0x08, 0, 0x8E);
    idt64_set_gate(19, (uint64_t)isr19, 0x08, 0, 0x8E);
    idt64_set_gate(20, (uint64_t)isr20, 0x08, 0, 0x8E);
    idt64_set_gate(21, (uint64_t)isr21, 0x08, 0, 0x8E);
    idt64_set_gate(22, (uint64_t)isr22, 0x08, 0, 0x8E);
    idt64_set_gate(23, (uint64_t)isr23, 0x08, 0, 0x8E);
    idt64_set_gate(24, (uint64_t)isr24, 0x08, 0, 0x8E);
    idt64_set_gate(25, (uint64_t)isr25, 0x08, 0, 0x8E);
    idt64_set_gate(26, (uint64_t)isr26, 0x08, 0, 0x8E);
    idt64_set_gate(27, (uint64_t)isr27, 0x08, 0, 0x8E);
    idt64_set_gate(28, (uint64_t)isr28, 0x08, 0, 0x8E);
    idt64_set_gate(29, (uint64_t)isr29, 0x08, 0, 0x8E);
    idt64_set_gate(30, (uint64_t)isr30, 0x08, 0, 0x8E);
    idt64_set_gate(31, (uint64_t)isr31, 0x08, 0, 0x8E);

    extern void isr32(void); extern void isr33(void);
    idt64_set_gate(32, (uint64_t)isr32, 0x08, 0, 0x8E);
    idt64_set_gate(33, (uint64_t)isr33, 0x08, 0, 0x8E);

    /* Device IRQ vectors 34..47 (IRQ2..IRQ15). These lines stay masked at the PIC
     * until a ring-3 driver binds one via SYS_IRQ_REGISTER, but their IDT gates
     * must exist so that unmasking a line delivers into interrupt_handler64 (the
     * IRQ->notification bridge) rather than faulting on an absent gate. */
    extern void isr34(void); extern void isr35(void); extern void isr36(void); extern void isr37(void);
    extern void isr38(void); extern void isr39(void); extern void isr40(void); extern void isr41(void);
    extern void isr42(void); extern void isr43(void); extern void isr44(void); extern void isr45(void);
    extern void isr46(void); extern void isr47(void);
    idt64_set_gate(34, (uint64_t)isr34, 0x08, 0, 0x8E);
    idt64_set_gate(35, (uint64_t)isr35, 0x08, 0, 0x8E);
    idt64_set_gate(36, (uint64_t)isr36, 0x08, 0, 0x8E);
    idt64_set_gate(37, (uint64_t)isr37, 0x08, 0, 0x8E);
    idt64_set_gate(38, (uint64_t)isr38, 0x08, 0, 0x8E);
    idt64_set_gate(39, (uint64_t)isr39, 0x08, 0, 0x8E);
    idt64_set_gate(40, (uint64_t)isr40, 0x08, 0, 0x8E);
    idt64_set_gate(41, (uint64_t)isr41, 0x08, 0, 0x8E);
    idt64_set_gate(42, (uint64_t)isr42, 0x08, 0, 0x8E);
    idt64_set_gate(43, (uint64_t)isr43, 0x08, 0, 0x8E);
    idt64_set_gate(44, (uint64_t)isr44, 0x08, 0, 0x8E);
    idt64_set_gate(45, (uint64_t)isr45, 0x08, 0, 0x8E);
    idt64_set_gate(46, (uint64_t)isr46, 0x08, 0, 0x8E);
    idt64_set_gate(47, (uint64_t)isr47, 0x08, 0, 0x8E);

    extern void isr128(void);
    idt64_set_gate(0x80, (uint64_t)isr128, 0x08, 0, 0xEE);

#ifdef SMP
    extern void isr64(void);    /* LAPIC timer (per-CPU preemption tick) */
    extern void isr251(void);   /* TLB-shootdown IPI */
    idt64_set_gate(0x40, (uint64_t)isr64,  0x08, 0, 0x8E);
    idt64_set_gate(0xFB, (uint64_t)isr251, 0x08, 0, 0x8E);
#endif

    idt64_ptr.limit = sizeof(idt64) - 1;
    idt64_ptr.base  = (addr_t)&idt64[0];

    __asm__ volatile ("lidt %0" : : "m"(idt64_ptr));

    keyboard_init();
    serial_init();   /* COM1/COM2 baud setup (the 64-bit boot's only caller) */
    pit_init();      /* periodic timer tick for preemptive scheduling */
}

/* Load the shared kernel IDT on an application processor. The IDT table is
 * global and identical for every CPU, so an AP just points IDTR at it. */
void ap_load_idt(void) {
    __asm__ volatile ("lidt %0" :: "m"(idt64_ptr) : "memory");
}

uint64_t page_fault_handler(struct regs *r) {
    addr_t fault_addr;
    asm volatile("mov %%cr2, %0" : "=r"(fault_addr));

    uint32_t err = r->err_code;
    int cur = get_current_task();
    if (cur > 0 && (fault_addr >= USER_AREA_BASE || fault_addr >= 0xA00000)) {
        /* Ask the Rust handler first (CoW, etc.). action == 2 means fully handled.
         * Any other return value means "not handled"; fall through to the C demand
         * pager exactly once. The old code called handle_demand_page_fault twice:
         * once inside the (now-fixed) stub and once here, causing the second call to
         * see the page already present (-2) and mis-route the fault to the kill path. */
        int action = rust_handle_demand_page_fault(fault_addr, err, 0, 1);
        if (action == 2) {
            return 0;
        }
        if (handle_demand_page_fault(fault_addr, err) == 0) {
            return 0;
        }
    }
    bool allowed = rust_validate_page_fault(cur, fault_addr, err);

    if (!allowed) {
        struct interrupt_frame64 *f64 = (struct interrupt_frame64 *)r;
        int cur = get_current_task();
        /* Deliver SIGSEGV to a registered ring-3 handler instead of killing the
         * task (and without printing the fault banner). */
        if (cur > 0 && (f64->cs & 3) &&
            try_deliver_fault_signal(f64, cur, SIG_SEGV, fault_addr)) {
            return 0;
        }
        int killed = get_current_task();
        if (killed == 0 || (f64->cs & 3) == 0) {
            println("PAGE FAULT at ");
            print_hex(fault_addr);
            println(" err=");
            print_hex(err);
            println(" task=");
            print_hex(killed);
            println("Rejected by validator - killing task ");
            print_hex(killed);
            println("");
        }
        /* Same as the vector < 32 kill path: tear down (wake SYS_WAIT waiters)
         * and resume the next runnable task via its saved trap frame. */
        if (killed > 0) {
            task_teardown(killed);
            uint64_t rsp = task_exit_switch(killed);
            if (rsp) return rsp;
            f64->rip    = (uint64_t)resume_shell_after_fault;
            f64->cs     = 0x08;
            f64->rflags = 0x202;
            f64->rsp    = tasks[0].kernel_stack_top;
            f64->ss     = 0x10;
            return 0;
        }
        asm volatile("cli; hlt");
        return 0;
    }

    asm volatile("cli; hlt");
    return 0;
}

void interrupt_handler(struct regs *r) {
    if (r->int_no == 0x80) {
        syscall_handler(r);
    } else if (r->int_no == 14) {
        page_fault_handler(r);
    } else if (r->int_no < 32) {
        if (r->int_no == 1) {
            return;
        }
        println("Exception! Vector: ");
        print_hex(r->int_no);
        println(" at EIP=");
        print_hex(r->eip);
        println("");
        asm volatile("cli; hlt");
    } else if (r->int_no >= 32 && r->int_no < 48) {
        if (r->int_no == 32) {
            if (get_current_task() < MAX_TASKS && !tasks[get_current_task()].in_kernel) {
                uint32_t uesp = r->useresp;
                if (uesp > 0x400000 && (r->cs & 3) == 3) {
                    tasks[get_current_task()].esp = uesp;
                    tasks[get_current_task()].eip = r->eip;
                }
            }
            timer_handler();
        } else if (r->int_no == 33) {
            uint8_t scancode = inb(0x60);
            char c = ps2_translate(scancode);
            if (c) {
                keyboard_buffer[kb_tail] = c;
                kb_tail = (kb_tail + 1) % 256;
                if (kb_tail == kb_head) kb_head = (kb_head + 1) % 256;
            }
        }
        if (r->int_no >= 40) outb(0xA0, 0x20);
        outb(0x20, 0x20);
    }
}
