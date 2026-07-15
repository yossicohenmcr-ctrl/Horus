#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>


typedef uint64_t addr_t;
typedef uint64_t paddr_t;
typedef uint64_t vaddr_t;


#define BLOCK_SIZE              512
/* 4096 blocks x 512 B = 2 MiB volume. Sized so a single file can exceed the
 * direct+single-indirect range (12 + 64 = 76 blocks) and actually reach the
 * double-indirect region. Bounded to one bitmap block (BLOCK_SIZE*8 = 4096 bits)
 * for both the data and inode allocators; larger disks need multi-block bitmaps
 * (a documented follow-up). Grows the RAM vdisk buffer + per-block crypto-meta
 * arrays to ~2 MiB of kernel BSS. */
#define BLOCKS_PER_DISK         4096
#define PAGE_SIZE               4096
#define USER_PHYS_BASE          0x01000000
#define USER_PHYS_PAGES         16384
#define CNODE_SIZE              256
#define MAX_TASKS               64
#define MAX_CAPS_PER_TASK       128
#define KERNEL_RESERVED_CAPS    4
#define MAX_REV_SETS            8

/* Capacity of the per-object lineage-generation map. Mirrors LINEAGE_SLOTS in
 * rust/src/capability.rs, which is the authoritative table (an exact,
 * key-storing open-addressing map — not a bare hash); keep these two in sync.
 * The C side does not use this constant directly (it delegates every lineage
 * op through rust_lineage_check / rust_lineage_bump); it is kept for reference. */
#define MAX_LINEAGES            16384
#define USER_VIRT_BASE          0x0000000000400000ULL
#define USER_MAX_VADDR          0x0000000000800000ULL
#define USER_AREA_BASE          0x400000ULL
/* Fallback/initial kernel stack for the TSS RSP0/ESP0: the real boot stack,
 * which the boot code installs as the initial RSP/ESP and which is therefore
 * always mapped. Using the linker symbol instead of a magic high address keeps
 * the value valid (and mapped) on both 32- and 64-bit, and avoids truncating a
 * 64-bit address into the 32-bit legacy TSS esp0 field. The former value,
 * 0xFFFF8000FFFFF000, both overflowed uint32_t and pointed at unmapped memory,
 * so any path that fell back to it would have triple-faulted. */
extern uint8_t stack_top[];
#define KERNEL_TSS_STACK        ((uintptr_t)stack_top)
#define USER_ASPACE_PREMAP_PAGES 32
#define KERNEL_STACK_SIZE 32768
#define MAX_USERS               32
#define USER_HEAP_BASE              0x0000000001000000ULL
#define USER_MEM_MAX_COPY           (64*1024)
#define ASLR_HIGH_STACK_BASE        0x00007ff000000000ULL
#define USER_HIGH_STACK_WINDOW      (16*1024*1024ULL)
/* Image-base ASLR window (pages). The randomized base is USER_AREA_BASE +
 * [0, ASLR_MAX_LOAD_RANDOM_PAGES) pages. Bounded so the whole premap window
 * (base + USER_ASPACE_PREMAP_PAGES) stays within a single 2 MiB PD entry, which
 * lets create_user_pagedir map the image into one page table. */
#define ASLR_MAX_LOAD_RANDOM_PAGES  (512 - USER_ASPACE_PREMAP_PAGES)
#define ASLR_MAX_STACK_RANDOM_PAGES 4
#define ASLR_MAX_HEAP_GAP_PAGES     8
#define DEMO_TASK_STACK_TOP         0x00007fffe0000000ULL
#define AUDIT_LOG_SIZE          256
#define PASS_SALT_LEN           16
#define PASS_HASH_LEN           32
/* On-disk inodes are 240 bytes, so only 2 fit in a 512-byte block. (The old
 * `BLOCK_SIZE/128 = 4` overran the block buffer when writing inode 2 or 3.)
 * A _Static_assert next to the struct definition pins this to sizeof. */
#define INODES_PER_BLOCK        2
uint32_t rust_get_user_page_protection(uint32_t t,uint32_t v);
bool rust_user_page_is_noexec(uint64_t vaddr);
int rust_validate_fs_operation(uint32_t task_id, uint32_t op, uint32_t rights, const uint8_t *name, size_t nlen);
#define MAX_ENDPOINTS 64
#define IPC_MSG_MAX   256

/* Task states. */
#define TASK_DEAD          0
#define TASK_RUNNABLE      1
#define TASK_BLOCKED_IPC   2   /* blocked inside SYS_IPC_CALL waiting for a reply */
#define TASK_BLOCKED_NOTIF 3   /* blocked inside SYS_WAIT_NOTIFY waiting for a badge */
#define TASK_BLOCKED_WAIT  4   /* blocked inside SYS_WAIT until the target task exits */

struct endpoint {
    int      has_message;
    int      msg_len;
    int      sender_task;
    int      last_sender;
    int      blocked_waiter;   /* task id blocked in SYS_IPC_CALL on this endpoint, -1=none */
    uint8_t  msg[IPC_MSG_MAX];
};
extern struct endpoint endpoints[MAX_ENDPOINTS];

#define MAX_NOTIFICATIONS 64
struct notification {
    uint32_t pending_badge;    /* accumulated badge bits not yet consumed */
    int      blocked_waiter;   /* task id blocked in SYS_WAIT_NOTIFY here, -1=none */
};
extern struct notification notifications[MAX_NOTIFICATIONS];
/* Canonical task_info ABI. MUST stay byte-identical to the copy in
 * include/syscall.h — the kernel fills this
 * layout and ring-3 reads it across copy_to_user (SYS_GET_TASK_INFO). A prior
 * mismatch (kernel and userspace had different field orders) made `ps` read
 * garbage; keep all three in sync. */
struct task_info {
    uint32_t id;
    uint32_t state;
    uint32_t uid;
    uint32_t gid;
    uint32_t cr3;
    uint32_t eip;
    uint32_t heap_used;
    uint32_t caps_in_use;
    int      in_kernel;
    int      blocked_on;
    int      blocked_on_notif;
    char     name[32];
};
struct dir_entry { char name[32]; uint32_t ino; uint32_t type; uint32_t name_len; uint32_t inode; };
typedef struct platform_info {
    int family, model, stepping;
    int has_long_mode;
    char vendor[13];
    int has_smap;
    int has_smep;
    int has_aesni;
    int has_tsc;
    int has_sse;
    int has_sse2;
    int has_sse4_2;
    int has_rdrand;
    int has_invariant_tsc;
    int num_logical_cpus;
    int num_physical_cpus;
    uint64_t total_memory_bytes;
} platform_info_t;
extern platform_info_t platform;
#define MAX_CPUS 4
void users_init(void);


#define SYS_YIELD           0
#define SYS_PRINT           1
#define SYS_EXIT            2
#define SYS_GET_LINE        3
#define SYS_SBRK            10
#define SYS_WRITE           11
#define SYS_READ            12
#define SYS_OPEN            13
#define SYS_WAIT            17
#define SYS_GET_TASK_INFO   18
#define SYS_EXEC            19
#define SYS_GETPID          20

#define SYS_IPC_SEND   21
#define SYS_IPC_RECV   22
#define SYS_IPC_CALL   23
#define SYS_IPC_REPLY  24

#define SYS_NOTIFY          25
#define SYS_WAIT_NOTIFY     26

/* Distinct return code for syscalls whose capability check passed but whose
 * backing operation is not implemented (vs. -1 = denied/bad-arg). */
#include "errno.h"   /* shared, descriptive syscall error codes (SYS_ERR_*) */
#define SYS_RECEIVE_PROGRAM 27
#define SYS_SPAWN           28

#define SYS_GETUID   29
#define SYS_AUTH     30
#define SYS_SUDO     31
#define SYS_GET_PASS 32

#define SYS_USERADD   33
#define SYS_USERDEL   34
#define SYS_PASSWD    35
#define SYS_ROTATE_KEYS   36  
#define SYS_READ_AUDIT    37
#define SYS_FS_MINT_FILE  38
#define SYS_FS_LOOKUP     39
#define SYS_FS_CREATE     40
#define SYS_FS_DELETE     41
#define SYS_FS_READDIR    42
#define SYS_FS_GET_ROOT   43
#define SYS_FS_READ       44
#define SYS_FS_WRITE      45
#define SYS_REGISTER_STORAGE_BACKEND 46
#define SYS_BLOCK_READ   47
#define SYS_BLOCK_WRITE  48
#define SYS_REGISTER_FS_SERVER 49
#define SYS_CONNECT_FS_SERVER  50
#define SYS_CAP_REVOKE         51
#define SYS_AUDIT_DIGEST       52
#define SYS_PREEMPT_TRACE      53   /* PREEMPT_SELFTEST builds only; NOSYS otherwise */
#define SYS_SIGACTION          54   /* register this task's own fault-signal handler */
#define SYS_SIGRETURN          55   /* resume the pre-signal context (from a handler) */
/* Encrypted object-store API for the userspace FS server (see include/syscall.h). */
#define SYS_FS_INODE_ALLOC     56
#define SYS_FS_INODE_FREE      57
#define SYS_FBLOCK_READ        58
#define SYS_FBLOCK_WRITE       59
#define SYS_FS_STAT            60
#define SYS_FS_SET_SIZE        61
#define SYS_BRK                62
#define SYS_KILL               63   /* terminate a task; gated on a CAP_TCB cap to it */
#define SYS_EXEC_NAMED         64   /* replace the caller's image with a named embedded binary */
#define SYS_CAP_GRANT          65   /* delegate a capability into a supervised child's cspace */
#define SYS_SIGNAL             66   /* send a signal to a task held via CAP_TCB (async delivery) */
#define SYS_SIGMASK            67   /* (how, mask) -> old mask; block/unblock this task's own signals */
#define SYS_SPAWN_ARG          68   /* () -> the one-word argument this task was spawned with */
#define SYS_GET_ARGV           69   /* (char ***out) -> argc; writes the argv[] base to *out */
#define SYS_SPAWN_IMAGE        70   /* (image, len, arg, argv, argc) -> pid; spawn a child from a caller-supplied program image */
#define SYS_EXEC_IMAGE         71   /* (image, len, 0, argv, argc) -> replace the caller's own image with a caller-supplied one; no return on success */
#define SYS_SIGALTSTACK        72   /* (ss_sp, ss_size) -> 0; register this task's own alternate signal stack (ss_size 0 disables) */
#define SYS_IPC_SENDER         73   /* (ep, uint32_t *out_gid) -> uid; kernel-attested identity of the last sender on `ep` (unforgeable, set at login) */
#define SYS_FS_SET_META        74   /* (ino, mode, uid, gid) -> 0; persist an inode's owner/mode (object-store server only: uid 0 + CAP_BLOCK_DEV) */
#define SYS_IPC_REPLY_TO       75   /* (req_ep, msg, len) -> 0; reply to the task that sent the last request on req_ep (routed by kernel-recorded sender, not a shared reply endpoint) — multi-client safe */
#define SYS_IRQ_REGISTER       76   /* (irq, notif_slot) -> 0; ring-3 driver binds a hardware IRQ to a notification slot (CAP_IRQ naming the line) */
#define SYS_IRQ_ACK            77   /* (irq) -> 0; ring-3 driver re-unmasks the line after servicing the device (CAP_IRQ naming the line) */

/* Minimum size of a registered alternate signal stack (SYS_SIGALTSTACK); smaller
 * requests fail closed so a handler always has room for at least a shallow frame. */
#define SIG_ALTSTACK_MIN       2048
/* Inode metadata returned by SYS_FS_STAT (mirrors struct fs_stat in
 * include/syscall.h — keep byte-identical). */
struct fs_stat {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
};

/* Signal numbers delivered to a registered handler on a ring-3 fault. */
#define SIG_ILL                 4   /* illegal instruction (#UD) */
#define SIG_KILL                9   /* uncatchable terminate (SYS_SIGNAL: always default-kills) */
#define SIG_USR1               10   /* application-defined, for task-to-task signalling */
#define SIG_SEGV               11   /* invalid memory access (page fault / #GP) */
#define SIG_USR2               12   /* second application-defined signal */
#define SIG_TERM               15   /* polite terminate (default action if no handler) */
#define SIG_MAX                31   /* signal numbers are 1..31 */

/* SYS_SIGMASK `how` argument: how the supplied mask combines with the current
 * blocked set. */
#define SIG_SETMASK             0   /* replace the blocked set with `mask` */
#define SIG_BLOCK               1   /* add `mask` to the blocked set */
#define SIG_UNBLOCK             2   /* remove `mask` from the blocked set */

#define CAP_NULL                0
#define CAP_TCB                 1
#define CAP_NOTIFICATION        2
#define CAP_ENDPOINT            3
#define CAP_FRAME               4
#define CAP_USER                6
#define CAP_AUDIT               7
#define CAP_CONSOLE             8
#define CAP_ENCRYPTED_STORAGE   9
#define CAP_REVOCATION          10
#define CAP_BLOCK_DEV           11
/* Device-driver capabilities (ring-3 driver framework). New type constants only:
 * they do NOT change struct capability's layout, so the FFI offset asserts in
 * capability.c and rust/src/capability.rs are unaffected. */
#define CAP_IO_PORT             14   /* object = (base<<16)|count : grants those x86 I/O ports */
#define CAP_IRQ                 15   /* object = IRQ line number : lets the holder claim/ack it */
#define CAP_MMIO                16   /* object = phys base; badge = length (Phase 2 / VGA) */

/* Max distinct I/O-port windows a single driver task can be granted (cached on
 * the tcb for the TSS I/O bitmap). ATA needs 2 (0x1F0-0x1F7 and 0x3F6); the
 * console phase needs a handful more. */
#define HORUS_MAX_IO_RANGES     8

#define CAP_RIGHT_READ          (1u << 0)
#define CAP_RIGHT_WRITE         (1u << 1)
#define CAP_RIGHT_EXEC          (1u << 2)
#define CAP_RIGHT_GRANT         (1u << 3)
#define CAP_RIGHT_MINT          (1u << 4)
#define CAP_RIGHT_REVOKE        (1u << 5)
#define CAP_RIGHT_AUDIT_WRITE   (1u << 6)
#define CAP_RIGHT_ALL           (0xFFFFFFFFu)

#define AUDIT_AUTH          1
#define AUDIT_SUDO          2
#define AUDIT_USER_MGMT     3
#define AUDIT_CAP_OPERATION 4
#define AUDIT_FILE_ACCESS   5
#define AUDIT_IPC           6
#define AUDIT_FS            7

#define AUDIT_CAP_MINT      10
#define AUDIT_CAP_REVOKE    11
#define AUDIT_CAP_TRANSFER  12
#define AUDIT_FS_LOOKUP     20
#define AUDIT_FS_CREATE     21
#define AUDIT_FS_DELETE     22
#define AUDIT_FS_READ       23
#define AUDIT_FS_WRITE      24
#define AUDIT_IPC_GRANT     30
#define AUDIT_TASK_CREATE   40
#define AUDIT_TASK_EXIT     41


typedef struct regs {uint32_t eax;uint32_t ebx;uint32_t ecx;uint32_t edx;uint32_t esi;uint32_t edi;uint32_t ebp;uint32_t esp;uint32_t eip;uint32_t eflags;uint32_t int_no;uint32_t err_code;uint32_t useresp;uint32_t cs;uint32_t ds;uint32_t es;uint32_t fs;uint32_t gs;uint32_t ss;} regs_t;


typedef struct user_account {
    char     name[32];
    uint32_t uid;
    uint32_t gid;
    uint32_t auth_lockout_until;
    uint32_t auth_fail_count;
    uint8_t  salt[16];
    int      valid;
    uint8_t  pass_hash[32];   
    char     home[64];
    char     shell[32];
} user_account_t;


typedef struct audit_event {
    uint32_t type;
    uint32_t kind;
    uint32_t uid;
    uint32_t subject_uid;
    int      subject_task;
    uint64_t object;
    int      result;
    uint64_t timestamp;
    uint64_t arg0;
    uint64_t arg1;
    char     path[64];
    char     message[128];
} audit_event_t;


typedef struct program_header {
    uint32_t type;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint32_t flags;
    uint32_t align;
    char     name[32];      
    uint64_t size;          
    uint32_t magic;         
    uint32_t entry;
} program_header_t;


typedef struct capability {
    uint32_t type;
    uint32_t rights;
    uint64_t object;
    uint32_t badge;       /* application-level semantic tag; NEVER matched by revocation */
    uint32_t serial;
    uint32_t generation;
    uint32_t parent;      /* lineage link: immediate parent's serial (0 = primordial).
                           * The ONLY field revocation walks. Fills former padding,
                           * so sizeof(capability_t) is unchanged. See I2 in the audit. */
} capability_t;

/* Immutable identity snapshot of a capability, taken at lookup time and
 * reconfirmed at use time via cap_revalidate() to defend against lookup/use
 * TOCTOU. `object` is uint64_t to match capability_t.object exactly. */
typedef struct cap_snapshot {
    uint32_t serial;
    uint32_t generation;
    uint64_t object;
    int      valid;
} cap_snapshot_t;


/* Full interrupt trap frame pushed by isr_common_stub64 (src/kernel/lowlevel64.S):
 * the 15 general-purpose registers, then the vector + error code, then the CPU's
 * iret frame. A pointer to this is what interrupt_handler64 receives and what
 * the preemptive scheduler and the signal path save/restore per task. */
struct interrupt_frame64 {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

typedef struct tcb {
    uint32_t state;
    uint32_t caps_in_use;
    capability_t *cspace;
    uint32_t cspace_size;
    uint64_t tsc_base;
    uint32_t esp; uint32_t eip; uint32_t cr3; uint32_t priority; uint32_t cap_tcb; int auth_fail_count; int auth_lockout_until; int ipc_role; 
    
    uint32_t uid;
    uint32_t gid;
    char     name[32];
    uint8_t  user_file_master_key[32];
    int      has_file_key;

    
    uint64_t heap_start;
    uint64_t heap_current;
    uint64_t heap_end;

    
    int      in_kernel;
    int      blocked_on;
    int      blocked_on_notif;
    int      waiter;


    uint64_t kernel_stack_top;

    /* Preemptive scheduling: `saved_ksp` is the kernel-stack pointer at which
     * this task's full interrupt trap frame sits while it is not running (set
     * either by the timer ISR when the task is preempted, or fabricated at
     * spawn for a task that has not run yet). `runnable_ctx` is 1 once such a
     * resumable frame exists. The timer ISR resumes a task by loading
     * `saved_ksp` into %rsp and running the interrupt epilogue (pop regs;
     * iretq). See scheduler.c and src/kernel/lowlevel64.S. */
    uint64_t saved_ksp;
    uint32_t runnable_ctx;

    /* Signal handling: deliver a ring-3 fault to a user handler instead of the
     * summary kill. `sig_handler` is the handler's ring-3 entry (0 = none; the
     * task registers its own via SYS_SIGACTION). `in_signal` is set while a
     * handler runs, so a fault *inside* the handler falls through to the kill
     * path (no recursion). `sig_frame` is the full trap frame captured at
     * delivery, restored by SYS_SIGRETURN. See idt.c / syscall.c. */
    uint32_t sig_handler;
    uint32_t in_signal;
    struct interrupt_frame64 sig_frame;

    /* ASLR: per-task randomized image load base (and end), chosen at spawn for
     * PIE (ET_DYN) images. create_user_pagedir premaps the image window at
     * `image_base`; the flat/non-PIE fallback keeps the fixed USER_AREA_BASE.
     * Carved from padding so the struct size is unchanged. */
    uint32_t image_base;
    uint32_t image_end;

    /* Blocking IPC: set by h_ipc_call before yielding, consumed by ipc_block_switch
     * when the reply arrives and the waiter is resumed. */
    uint32_t ipc_reply_buf;    /* userspace ptr in the waiter's address space */

    /* Block intent recorded by a syscall handler *before* the frame is saved.
     * Non-zero (a TASK_BLOCKED_* value) means interrupt_handler64 must call
     * ipc_block_switch, which saves the trap frame first and only then publishes
     * the waiter so a cross-CPU notifier cannot patch a stale saved_ksp.
     * Object is in blocked_on (reply ep or wait tid) or blocked_on_notif. */
    uint32_t pending_block;

    /* Async signals. `pending_sigs` is a bitmask of queued signals (bit N =
     * signal N pending, 1..31), set by SYS_SIGNAL (gated on a CAP_TCB to this
     * task) or the fault path; the lowest-numbered *unmasked* one is delivered
     * into `sig_handler` when this task next returns to ring 3. `sig_mask` is the
     * set of currently-blocked signals (SYS_SIGMASK); a blocked signal stays
     * pending until unblocked. SIG_KILL can never be blocked. Carved from padding
     * so the struct size is unchanged. */
    uint32_t pending_sigs;
    uint32_t sig_mask;

    /* One-word argument handed to a task at spawn (SYS_SPAWN edx), retrieved by
     * the child via SYS_SPAWN_ARG. A fast path alongside the full argv below. */
    uint32_t spawn_arg;

    /* Full argument vector. The kernel marshals the spawner's argv strings onto
     * the child's initial user stack at spawn and records the count and the
     * user vaddr of the argv[] pointer array here; the child reads them with
     * SYS_GET_ARGV. Both 0 when spawned without arguments. */
    uint32_t argc;
    uint32_t argv_ptr;

    /* Alternate signal stack (SYS_SIGALTSTACK). When sig_altstack_size is
     * non-zero, a signal delivered while the task is not already running on the
     * altstack enters its handler on [sig_altstack_sp, +sig_altstack_size)
     * instead of the interrupted user stack; sig_on_stack is the SS_ONSTACK
     * guard, set on delivery to the altstack and cleared by SYS_SIGRETURN so a
     * nested signal does not re-use (and corrupt) the frame already on it. All
     * zero => run handlers on the interrupted stack (previous behaviour). Carved
     * from padding so the struct size is unchanged. */
    uint32_t sig_altstack_sp;
    uint32_t sig_altstack_size;
    uint32_t sig_on_stack;

    /* Ring-3 driver I/O ports: the port windows this task may touch, cached from
     * its held CAP_IO_PORT capabilities so set_tss_kernel_stack() can rebuild the
     * per-CPU TSS I/O-permission bitmap on a switch to a driver task without
     * scanning the cspace. `has_io_caps == 0` (the common case for every
     * non-driver task) keeps the bitmap all-deny and skips any rewrite, so the
     * fast path costs nothing. Populated by cap_cache_io_ports() when a
     * CAP_IO_PORT is installed/granted, and cleared on task-slot reuse. */
    uint16_t io_port_base[HORUS_MAX_IO_RANGES];
    uint16_t io_port_count[HORUS_MAX_IO_RANGES];
    uint32_t io_range_n;
    int      has_io_caps;
} tcb_t;

extern tcb_t tasks[MAX_TASKS];


/* Lineage/generation tracking is owned by the safe-Rust authority
 * (rust/src/capability.rs). The legacy C `lineages[]` table and its helpers
 * (lineage_register/lineage_revoke/next_lineage_id) have been removed to avoid a
 * C/Rust desync that allowed use-after-revoke; use rust_lineage_check /
 * rust_lineage_bump instead. */


typedef struct block_device {
    char name[32];
    uint64_t total_blocks;
    int (*read_block)(struct block_device *bd, uint64_t block, void *buf);
    int (*write_block)(struct block_device *bd, uint64_t block, const void *buf);
    void *private;
} block_device_t;

typedef struct virtual_disk {
    uint8_t *data;
    uint64_t size;
    uint64_t block_count;
} virtual_disk_t;

typedef struct fs_superblock {
    uint32_t magic;
    uint32_t version;            /* 4 = disk_key wrapped by password-derived KEK (LUKS-style) */
    uint64_t meta_start;         /* first block of the nonce/tag metadata region */
    uint32_t meta_blocks;        /* number of blocks in that region */
    uint32_t _pad;
    /* v5: write-ahead redo log. Multi-block updates (bitmap + inode + meta block +
     * data + this superblock's meta_hmac) are staged, committed to this region
     * with an HMAC-authenticated header, then applied to their home locations —
     * so a crash leaves the filesystem either fully before or fully after the
     * operation, and the meta_hmac can never desync (which previously bricked the
     * volume). One header sector + journal_blocks-1 data sectors. */
    uint64_t journal_start;
    uint32_t journal_blocks;
    uint32_t _pad_j;
    uint64_t inode_bitmap_start;
    uint64_t block_bitmap_start;
    uint64_t data_bitmap_start;
    uint64_t inode_table_start;
    uint64_t data_start;
    uint64_t inode_count;
    uint64_t block_count;
    uint64_t total_blocks;
    uint32_t block_size;
    uint8_t  volume_key_salt[16]; /* per-volume HKDF diversifier */
    uint8_t  volume_key[16];      /* unused; kept for struct layout compat */
    uint32_t generation;
    /* v4: password-wrapped disk key — disk_key never stored in plaintext on disk.
     * disk_key is the root of all block key and metadata MAC derivation; it is
     * sealed here with a KEK = Argon2id(password, kek_salt) so the volume is
     * unreadable without the passphrase, even with physical disk access. */
    uint8_t  kek_salt[32];           /* Argon2id salt for KEK (no kernel_pepper: must
                                       * be reproducible across reboots from the same pwd) */
    uint8_t  wrapped_key_nonce[12];  /* AEAD nonce for disk_key sealing */
    uint8_t  wrapped_key_ct[32];     /* AEAD ciphertext of disk_key[32] */
    uint8_t  wrapped_key_tag[16];    /* AEAD auth tag; wrong pwd → open fails → locked */
    uint8_t  meta_hmac[32];          /* HMAC-SHA256(meta_mac_key, g_block_meta[]);
                                       * recomputed on every metadata flush, verified on
                                       * unlock to detect partial nonce/tag rollback */
} fs_superblock_t;

typedef struct on_disk_inode {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime, mtime, ctime;
    uint64_t direct[12];
    uint64_t indirect;
    uint64_t double_indirect;
    uint8_t  key_material[32];
    uint8_t  file_key[16];
    uint8_t  file_iv[16];
    uint32_t links;
    uint32_t generation;
    uint32_t checksum;
} on_disk_inode_t;
_Static_assert(sizeof(struct on_disk_inode) * INODES_PER_BLOCK <= BLOCK_SIZE,
               "on_disk_inode too large: INODES_PER_BLOCK inodes must fit one block");

typedef struct mounted_fs {
    int     mounted;             /* 1 after storage_mount reads a valid superblock */
    int     unlocked;            /* 1 after storage_unlock derives disk_key from password */
    block_device_t *bd;
    fs_superblock_t sb;
    uint8_t volume_key[16];      /* HKDF(disk_key, volume_key_salt, "horus-volume-key-v2") */
    uint8_t *inode_cache;
    uint8_t disk_key[32];        /* plaintext disk_key in RAM after unlock; zeroed on error */
    uint8_t meta_mac_key[32];    /* HKDF(disk_key, volume_key_salt, "horus-meta-mac-v1") */
    uint8_t journal_mac_key[32]; /* HKDF(disk_key, volume_key_salt, "horus-journal-mac-v1") */
} mounted_fs_t;

/* The legacy capfs object type (struct fs_object / fs_objects[]) and its
 * at-rest AEAD were removed with the capfs engine; the encrypted fs_server is
 * now the only filesystem. */
extern uint8_t kernel_pepper[16];

extern int fs_server_task_id;
extern int fs_server_listen_ep_idx;


extern char keyboard_buffer[256];
extern uint32_t kb_head;
extern uint32_t kb_tail;

typedef struct spinlock {
    volatile uint32_t locked;
} spinlock_t;

extern spinlock_t storage_lock;
extern spinlock_t cap_lock;
extern spinlock_t page_lock;
/* Capability seqlock version (audit 3.1). Bumped to odd on cap_lock acquire and
 * to even on release (see spin_lock/spin_unlock in scheduler.c); the lock-free
 * cap_lookup reads it around its field reads to obtain a torn-free snapshot
 * against a concurrent cap mutation on another CPU. */
extern uint32_t cap_seq;



int  get_current_task(void);
void set_current_task(int v);
/* Request a voluntary yield from a syscall handler; interrupt_handler64 performs
 * the full-context switch via sched_yield_switch. Not a cooperative mid-kernel switch. */
void yield(void);
/* Set by yield() to the yielding task id; consumed by interrupt_handler64. -1 = none. */
extern volatile int g_want_yield;
/* Idle this CPU (sti; hlt loop). The only inter-task path is full-context. */
void __attribute__((noreturn)) kernel_idle(void);
/* Enter a task that already has a fabricated/saved trap frame (do_spawn /
 * sched_prepare_user_context). Noreturn: pop+iretq into ring 3. */
void __attribute__((noreturn)) sched_enter_user(int tid);
/* Voluntary yield with a live trap frame; returns the kernel %rsp for the ISR epilogue. */
uint64_t sched_yield_switch(int cur, uint64_t frame_rsp);
/* Terminate task `id`: wake any SYS_WAIT waiter, drop its signal handler, mark it
 * dead (state 0) and release its SMP running-CPU guard. Does NOT switch away from
 * the caller — the SYS_EXIT/SYS_KILL paths handle that. */
void task_teardown(int id);
/* Resume the next runnable task after `dead` terminated (returns its saved kernel
 * %rsp for the ISR epilogue), or 0 if nothing else is runnable. See scheduler.c. */
uint64_t task_exit_switch(int dead);
/* Re-enter task `t` via the fresh context SYS_EXEC_NAMED fabricated for it (same
 * task, replaced image). Returns its saved kernel %rsp for the ISR epilogue. */
uint64_t exec_reenter_switch(int t);
/* Set by h_exec_named; consumed by interrupt_handler64 to resume the exec'd task
 * via exec_reenter_switch instead of the old image's trap frame. -1 = none. */
extern int g_exec_reenter_task;
char console_getc(void);
void console_putc(char c);
void console_puts(const char *s);
void println(const char *s);
void print(const char *s);
void print_char(char c);
#ifdef DEBUG_SHELL
/* Defined in syscall.c under DEBUG_SHELL; declared here so the in-kernel debug
 * shell (main.c) and the SYS_EXEC_CMD path (syscall.c) can call it without an
 * implicit declaration (a hard error under modern GCC). */
int process_user_command(const char *cmd);
#endif
void print_hex(uint64_t v);
void print_decimal(uint64_t v);
void print_hrule(uint8_t color);
void set_text_colour(uint8_t color);
uint64_t read_tsc(void);
uint32_t get_system_ticks(void);
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void secure_zero(void *p, size_t n);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
void dump_kernel_log(void);
void syscall_handler(struct regs *r);
void resume_shell_after_fault(void);
void print_hex64(uint64_t v);
void timer_handler(void);
void pit_init(void);
void smp_maybe_shootdown(uint64_t v);
int smp_get_online_count(void);

/* Preemptive scheduling (scheduler.c). preempt_on_tick is called from the timer
 * ISR with the current trap-frame pointer and the interrupted CS; it returns the
 * kernel %rsp to resume on (unchanged for no-switch, or the next task's saved
 * frame). sched_prepare_user_context fabricates an initial resumable frame for a
 * freshly spawned user task. sched_enable_preemption arms the timer switch once
 * boot is past its delicate single-threaded init. */
uint64_t interrupt_handler64(struct interrupt_frame64 *frame);
uint64_t preempt_on_tick(uint64_t frame_rsp, uint64_t interrupted_cs);
void sched_prepare_user_context(int id, uint64_t entry, uint64_t user_rsp);
/* Called from interrupt_handler64 when the caller has pending_block set (or is
 * already in a BLOCKED_* state). Saves the trap frame first, then publishes the
 * waiter under the IPC lock so a cross-CPU wake always patches a valid frame.
 * Returns the kernel %rsp for the ISR epilogue (next task, or same if already
 * satisfied). */
uint64_t ipc_block_switch(int blocked_task, uint64_t frame_rsp);
/* Publish pending_block after saved_ksp is valid. Returns 1 if the task is now
 * blocked (switch away), 0 if the wait completed immediately (resume same). */
int ipc_publish_pending_block(int cur);
/* Undo a published block (no other runnable task to switch to). */
void ipc_unpublish_block(int cur);
void sched_enable_preemption(void);

/* Signal delivery (idt.c): on a ring-3 fault, redirect the trap frame into the
 * task's registered handler instead of killing it. Returns 1 if a signal was
 * delivered (caller returns into the handler), 0 to fall through to the kill
 * path. See the fault sites in interrupt_handler64 / page_fault_handler. */
int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                             uint32_t signum, uint64_t fault_addr);
/* Signatures MUST match rust/src/memory.rs exactly (return types and the u32
 * n_pages width — they previously drifted to `int`). */
int32_t  rust_page_ref_dec(uint32_t phys, uint16_t *refcounts, uint32_t n_pages);
uint16_t rust_page_ref_inc(uint32_t phys, uint16_t *refcounts, uint32_t n_pages);
bool     rust_page_is_valid_user_phys(uint32_t phys, uint32_t n_pages);
bool     rust_page_refcounts_register(const uint16_t *refcounts, uint32_t n_pages);
bool     rust_cow_copy_required(bool is_cow, bool is_write, uint16_t ref_count);
/* Validate a would-be ring-3 signal-handler entry: it must lie in the user code
 * window so the kernel never iretq's ring 3 to the stack, the kernel image, or
 * an unmapped address. Pure value predicate (no pointer deref); fails closed. */
bool     rust_signal_handler_addr_ok(uint32_t vaddr);

/* Device-capability range validators (rust/src/device.rs), for the ring-3 driver
 * framework: decide from an unforgeable CAP_IO_PORT / CAP_MMIO exactly which I/O
 * ports / physical MMIO region a driver may touch. Fail-closed, overflow-safe,
 * pure value predicates (no pointer deref). */
bool     rust_io_port_window_ok(uint64_t cap_object);
bool     rust_io_port_range_ok(uint64_t cap_object, uint32_t req_base, uint32_t req_count);
bool     rust_mmio_region_ok(uint64_t cap_object, uint64_t cap_len,
                             uint64_t req_phys, uint64_t req_len);

/* Centralized capability serial allocation (wrap logic lives in Rust). */
uint32_t rust_cap_alloc_serial(uint32_t *next_serial);

/* Ed25519 signature verification (rust/src/ed25519.rs), for verified boot.
 * Returns 1 iff `sig` (64 bytes: R||S) is a valid signature by `public_key`
 * (32 bytes) over `msg[0..msg_len]`. Verify-only: the kernel never signs. */
int rust_ed25519_verify(const uint8_t *public_key, const uint8_t *sig,
                        const uint8_t *msg, size_t msg_len);
#ifdef VBOOT_SELFTEST
/* Verified-boot self-test (verified_boot.c): verify a signed manifest against an
 * embedded Ed25519 public key and prove the enforce-or-halt boot gate. Prints a
 * marker and halts. See docs/BOOT_INTEGRITY.md. */
void verified_boot_selftest(void) __attribute__((noreturn));
#endif
#ifdef VBOOT_ENFORCE
/* Real-image verified boot (verified_boot.c): verify the loaded kernel image
 * against an Ed25519 signature over its own bytes, anchored to an embedded
 * public key. Returns on success (boot continues); halts on failure. See
 * docs/BOOT_INTEGRITY.md. */
void verified_boot_enforce(void);
#endif

void terminal_init(void);
void clear_screen(void);
void print_blanks(int n);
void print_boot_timestamp(void);
void print_section(const char *title, uint8_t color);
void idt_init64(void);
void pic_init(void);
void set_tss_kernel_stack(uint64_t kstack_top);
/* Load the incoming ring-3 task's granted I/O ports into the running CPU's TSS
 * I/O-permission bitmap (default-deny for a task with no CAP_IO_PORT). Called
 * from set_current_task on every context switch; a no-op fast path when neither
 * the outgoing nor incoming task holds port caps. `task` may be NULL (deny). */
void tss_load_io_bitmap(int cpu, const tcb_t *task);
void cpu_detect_features(void);
void ramfs_init(void);
int ata_init(void);   /* probe primary master; 1 = ATA disk present, 0 = absent */
int  ata_read(uint32_t lba, void *buf, uint32_t sectors);
int  ata_write(uint32_t lba, const void *buf, uint32_t sectors);
void scheduler_init(void);
void smp_bringup(void);
void aslr_init_seed(void);
void spawn_initial_userspace_shell(void);
/* Launch the ring-3 init process (PID-1) — the first userspace task, which then
 * spawns and supervises the shell. Replaces spawn_initial_userspace_shell at boot. */
void spawn_initial_userspace_init(void);
int cpu_has_aesni(void);
void cpu_enable_protections(void);
void paging_init(void);

void cap_init(void);
/* Rebuild a task's cached CAP_IO_PORT windows (tcb.io_port_*) from its live
 * cspace, so the TSS I/O bitmap loaded on a context switch reflects exactly the
 * port capabilities the task currently holds (revocation-safe: a revoked/zeroed
 * CAP_IO_PORT simply is not found). Called after any cap install/grant onto the
 * task and defensively at switch time for driver tasks. */
void cap_cache_io_ports(int pid);
/* True iff the current task holds a CAP_IRQ capability naming exactly `irq`.
 * The least-privilege gate for the SYS_IRQ_REGISTER / SYS_IRQ_ACK bridge. */
int caller_holds_irq_cap(int irq);
/* IRQ -> notification bridge back ends (src/kernel/idt.c). register binds a line
 * to a driver's notification slot and unmasks it; ack re-unmasks after service. */
int irq_bridge_register(int irq, uint32_t notif_slot, int task);
int irq_bridge_ack(int irq);
/* Deliver a badge to a notification slot, waking any blocked waiter (syscall_ipc.c).
 * Also called from interrupt context by the IRQ bridge. */
int sys_notify(uint32_t notif_slot, uint32_t badge);
capability_t *cap_lookup(uint32_t slot, uint32_t required_rights);
/* Non-retrying variant of cap_lookup for callers that ALREADY hold cap_lock
 * (kcap_lookup via cap_mint/cap_transfer, task_kill_authorized via
 * SYS_KILL/SYS_SIGNAL, and SYS_CAP_GRANT). Using the public cap_lookup there
 * would spin forever on the odd seq the caller's own cap_lock section set.
 * Callers must hold cap_lock (or run single-threaded at boot). */
capability_t *cap_lookup_locked(uint32_t slot, uint32_t required_rights);
bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights);
bool cap_transfer(uint32_t dest_slot, uint32_t src_slot);
bool cap_move(uint32_t dest_slot, uint32_t src_slot);
bool cap_revoke(uint32_t slot);
bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot);
bool has_encrypted_storage_cap(void);


uint32_t cap_alloc_fresh_serial(void);

/* Lookup/use TOCTOU defense: snapshot a capability's identity, then
 * revalidate the slot still holds that exact identity (with the required
 * rights) at the point of use. Returns NULL on revoke/re-mint/generation bump. */
cap_snapshot_t cap_snapshot(const capability_t *c);
capability_t *cap_revalidate(uint32_t slot, uint32_t required_rights,
                             const cap_snapshot_t *snap);


capability_t *rust_cap_lookup(capability_t *cspace, uint32_t sz, uint32_t slot, uint32_t rights);
bool rust_cap_mint(capability_t *dest_array, uint32_t sz, uint32_t dest_slot,
                   uint32_t src_slot, uint32_t new_rights, uint32_t *next_serial, uint32_t caps_in_use);
bool rust_cap_transfer(capability_t *dest_array, uint32_t sz, uint32_t dest_slot,
                       uint32_t src_slot, uint32_t *next_serial);
bool rust_cap_revoke(capability_t *cspace, uint32_t sz, uint32_t slot, uint32_t *next_serial);
bool rust_cap_revoke_by_values(capability_t *cspace, uint32_t sz, uint32_t target_serial, uint32_t target_badge, uint64_t target_obj);

/* One capability space, for the system-wide revocation sweep. Layout MUST match
 * `struct CSpaceDesc` in rust/src/capability.rs. */
typedef struct cspace_desc {
    capability_t *caps;
    uint32_t      size;
    uint32_t     *caps_in_use; /* owning task's counter; NULL to skip accounting */
} cspace_desc_t;

/* Authoritative, system-wide revocation: revokes target_slot in target_cspace
 * and sweeps every cspace in `spaces` for derived copies of the same lineage.
 * Must be called under cap_lock so the snapshot is stable. */
bool rust_cap_revoke_global(capability_t *target_cspace, uint32_t target_cspace_size,
                            uint32_t target_slot, uint32_t *target_caps_in_use,
                            const cspace_desc_t *spaces, uint32_t space_count,
                            uint32_t *next_serial);

bool rust_validate_page_fault(uint32_t t, uint32_t a, uint32_t e);
int  rust_handle_command(const uint8_t *cmd, size_t len);


int  do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *pass);
int  do_userdel(uint32_t uid);
int  do_passwd(uint32_t target, const char *newpass);
int derive_and_store_user_file_key(uint32_t uid, const char *material, size_t material_len);


int  storage_mount(block_device_t *bd);
/* Unlock storage at login time: on first boot formats+seals; on subsequent boots
 * derives KEK from password, unwraps disk_key, derives volume/MAC keys, and
 * verifies the metadata HMAC.  Must be called after verify_password succeeds. */
int  storage_unlock(const char *password, size_t plen);
/* Re-wrap disk_key with a new password-derived KEK.  Call after a successful
 * password change so the on-disk wrapped key stays in sync with the login hash.
 * Requires storage to already be unlocked (disk_key in RAM).  Generates fresh
 * kek_salt + nonce for forward security, then writes the updated superblock. */
int  storage_rekey(const char *new_password, size_t plen);
int  storage_read_file_block(mounted_fs_t *mfs, uint64_t ino, uint64_t block, void *buf);
int  storage_write_file_block(mounted_fs_t *mfs, uint64_t ino, uint64_t block, const void *buf);
mounted_fs_t *storage_get_mounted_fs(void);
block_device_t *storage_get_default_device(void);
void storage_set_default_device(block_device_t *bd);
int storage_init(void);
int64_t storage_alloc_block(block_device_t *bd, fs_superblock_t *sb);
void storage_free_block(block_device_t *bd, fs_superblock_t *sb, uint64_t block);
int64_t storage_alloc_inode(block_device_t *bd, fs_superblock_t *sb);
void storage_free_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino);
int  storage_read_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino, on_disk_inode_t *inode_out);
int  storage_write_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino, const on_disk_inode_t *inode);
/* Free all data blocks (direct + single-indirect) and the inode itself. Used by
 * the FS server's delete path via SYS_FS_INODE_FREE. */
int  storage_free_inode_blocks(mounted_fs_t *mfs, uint64_t ino);
/* Derives 64 bytes of per-block subkeys (enc_key32 ‖ mac_key32) from the volume
 * key via HKDF-SHA256, binding (ino, block) into the info string so every block
 * gets independent keys. */
int  storage_derive_block_keys(uint64_t ino, uint64_t block,
                               const uint8_t *vol_key, size_t vol_key_len,
                               uint8_t *enc_key32, uint8_t *mac_key32);
int  storage_block_read(uint64_t block, void *buf);
int  storage_block_write(uint64_t block, const void *buf);
int  do_rotate_keys(void);


int  ramfs_open(const char *path, int flags);
int  ramfs_create(const char *path, int mode);
int  ramfs_write(int fd, const void *buf, size_t len);
int  ramfs_read(int fd, void *buf, size_t len);
char serial2_read_char(void);
void serial_write_char(char c);


/* The legacy capfs syscalls (sys_fs_mint_file / lookup / create / delete /
 * readdir / get_root / read / write) were removed; those syscall numbers now
 * fail closed. */


int  copy_from_user(void *kdst, const void *usrc, size_t len);
int  copy_to_user(void *udst, const void *ksrc, size_t len);
int  user_protect_page(uint64_t vaddr, int writable, int executable);
uint64_t user_lookup_pte(uint64_t cr3, uint64_t vaddr);
#ifdef ELF_SELFTEST
void elf_loader_selftest(void);
#endif
#ifdef PREEMPT_SELFTEST
void preempt_selftest(void);
#endif
#ifdef SIGNAL_SELFTEST
void signal_selftest(void);
#endif
#ifdef FS_SELFTEST
void fs_selftest(void);
#endif
#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST)
/* Shared by both FS harnesses: the newlib self-test also spawns + provisions
 * the fs_server so its client can exercise the real libc file paths. */
int  cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
#endif
#ifdef NEWLIB_SELFTEST
void newlib_selftest(void);
#endif
#ifdef BIGFILE_SELFTEST
void bigfile_selftest(void);
#endif
#ifdef SMP_SELFTEST
void smp_selftest(void);
#endif
#ifdef PROC_SELFTEST
void proc_selftest(void);
#endif
#ifdef NOTIFY_SELFTEST
void notify_selftest(void);
#endif


int  sys_ipc_send(uint32_t ep_slot, const void *msg, size_t len);
int  sys_ipc_recv(uint32_t ep_slot, void *msg, size_t max_len);


bool     capability_validate_generation(const capability_t *cap);
uint32_t rust_lineage_bump(uint64_t obj);
bool     rust_lineage_check(uint64_t obj, uint32_t gen);

/* ---- Cryptography & entropy (audited primitives implemented in Rust) ---- */
/* SHA-256 suite */
int  rust_password_hash(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len);
/* Argon2id password hash (rust/src/argon2.rs). memory-hard; `p_cost` lanes;
 * `mem` is a caller-owned scratch buffer of `mem_words` u64 (>= 128 * blocks,
 * blocks a multiple of 4*p_cost). Returns 0/-1. */
int  rust_argon2id_hash(const uint8_t *pwd, size_t pwd_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t t_cost, uint32_t m_cost, uint32_t p_cost,
                        uint64_t *mem, size_t mem_words,
                        uint8_t *out, size_t out_len);
int  rust_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len, uint8_t *out32);
/* Tamper-evident audit log (rust/src/audit.rs). */
int  rust_audit_chain_init(const uint8_t *key, size_t key_len, uint8_t *out_head32);
int  rust_audit_chain_record(const uint8_t *key, size_t key_len, uint64_t seq,
                             const uint8_t *event, size_t event_len,
                             uint8_t *head32, uint8_t *out_mac32);
int  rust_audit_entry_mac(const uint8_t *key, size_t key_len, uint64_t seq,
                          const uint8_t *event, size_t event_len, uint8_t *out_mac32);
int  rust_audit_mac_eq(const uint8_t *a32, const uint8_t *b32);
int  rust_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len);
/* ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (12-byte nonce, 16-byte tag).
 * seal encrypts buf[0..len] in place and writes a 16-byte tag; open verifies
 * the tag in constant time and decrypts in place only if authentic (returning
 * 0), else zeroes buf and returns -1. */
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN   16

/* Crypto metadata region: one 32-byte slot per physical block (nonce+tag+present+3pad).
 * 16 slots fit in one 512-byte sector → 64 sectors cover all BLOCKS_PER_DISK=1024 slots.
 * These constants drive both the on-disk layout (storage_format) and the in-memory
 * flush granularity (storage_encrypt_block). */
#define META_ENTRY_SIZE        32   /* must equal sizeof(struct block_crypto_meta) — asserted in storage.c */
#define META_ENTRIES_PER_BLOCK (BLOCK_SIZE / META_ENTRY_SIZE)
#define META_BLOCKS_COUNT      (BLOCKS_PER_DISK / META_ENTRIES_PER_BLOCK)
int  rust_aead_seal(const uint8_t *enc_key, const uint8_t *mac_key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *buf, size_t len, uint8_t *tag_out);
int  rust_aead_open(const uint8_t *enc_key, const uint8_t *mac_key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *buf, size_t len, const uint8_t *tag);
/* ps presentation (rust/src/ps.rs): NUL-terminated static state label. */
const char *rust_task_state_name(uint32_t state);
/* Authentication / sudo throttling + privilege policy (rust/src/auth.rs) */
uint32_t rust_sudo_frame_rights(void);
bool     rust_auth_is_locked(uint64_t lockout_until, uint64_t now);
void     rust_auth_on_failure(uint32_t fail_count, uint64_t now,
                              uint32_t *out_count, uint64_t *out_lockout_until);
bool     rust_auth_global_locked(uint64_t now);
void     rust_auth_global_on_failure(uint64_t now);
void     rust_auth_global_on_success(void);
/* ChaCha20 CSPRNG */
void     rust_rng_add_entropy(const uint8_t *data, size_t len);
void     rust_rng_fill(uint8_t *out, size_t len);
uint64_t rust_rng_u64(void);
bool     rust_rng_is_seeded(void);
bool     rust_rdrand_u64(uint64_t *out);

/* C-side entropy helpers (crypto.c) */
int  cpu_has_rdrand(void);
void entropy_init(void);            /* gather hardware/timing entropy, seed CSPRNG */
void entropy_add_sample(uint64_t s);/* mix an opportunistic entropy sample */
void secure_random_bytes(void *out, size_t n);

/* Password KDF cost (PBKDF2-HMAC-SHA256 iterations). */
#define PASSWORD_KDF_ITERATIONS 120000U   /* legacy PBKDF2 cost (no longer used) */

/* Argon2id password-hashing cost (memory-hard, unlike the former PBKDF2):
 * m_cost KiB of scratch (== 1 KiB blocks) filled t_cost times over p_cost lanes.
 * 4 MiB / 3 passes / 1 lane is a strong, boot-feasible profile. The scratch
 * buffer is sized for the worst case at build time; password hashing runs
 * non-preemptibly under a syscall, so one shared static buffer is safe.
 * Adjust these three to retune cost; the scratch buffer resizes automatically.
 * (m_cost must be a multiple of 4*p_cost; the Rust side rounds down if not.) */
#define ARGON2_M_COST_KIB   4096U
#define ARGON2_T_COST       3U
#define ARGON2_P_COST       1U

/* Maximum heap size per task.  The demand pager allocates physical pages lazily
 * so this is a virtual address ceiling, not a pre-committed reservation.
 * 64 MiB fits comfortably in the 32-bit low-memory window without colliding
 * with typical stack placements (stacks grow down from below 0x80000000). */
#define USER_HEAP_MAX_SIZE  (64U * 1024U * 1024U)
/* Shared Argon2id wrapper using the kernel's single pre-allocated scratch buffer.
 * Safe only for sequential (non-concurrent) calls — all kernel Argon2id users
 * (login hash + KEK derivation) run sequentially inside a single syscall. */
int kernel_argon2id(const uint8_t *pwd, size_t plen,
                    const uint8_t *salt, size_t salt_len,
                    uint8_t *out, size_t out_len);


#define CAP_DIR                 12
#define CAP_FILE                13

#define CAP_RIGHT_FS_LOOKUP     (1u << 10)
#define CAP_RIGHT_FS_CREATE     (1u << 11)
#define CAP_RIGHT_FS_DELETE     (1u << 12)
#define CAP_RIGHT_FS_READ       (1u << 13)
#define CAP_RIGHT_FS_WRITE      (1u << 14)

#define FS_OBJ_DIR              2
#define FS_OBJ_FILE             1
#define FS_DATA_SIZE            4096
#define FS_MAX_CHILDREN         32


/* The capfs_* engine (legacy capability filesystem) was removed. */


int  ramfs_list(char *buf, size_t buflen);


void create_task(int id, uint64_t entry, uint64_t stack_top, uint64_t image_base);
void create_user_pagedir(uint32_t id);
/* Floor of always-live kernel state in low memory; a user heap must never grow
 * at or above this (it would shadow kernel data on the task's own CR3). */
uint32_t kernel_lowmem_critical_floor(void);
void switch_cr3(uint64_t cr3);
void drop_to_ring3(uint64_t entry, uint64_t stack);
void aslr_mix_entropy(uint64_t val);
uint32_t aslr_random_offset(uint32_t max);
addr_t aslr_random_stack_top(addr_t top);

#endif
