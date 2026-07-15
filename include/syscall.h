#ifndef USERSPACE_SYSCALL_H
#define USERSPACE_SYSCALL_H

#include <stdint.h>
#include <stddef.h>
#include "errno.h"   /* shared, descriptive syscall error codes (SYS_ERR_*) */

/* MUST stay byte-identical to the copy in src/include/kernel.h
 * (SYS_GET_TASK_INFO ABI). */
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

struct program_header {
    uint32_t magic;
    uint32_t entry;
    uint32_t size;
    char     name[32];
};

struct audit_event {
    uint32_t timestamp;
    uint32_t type;
    uint32_t subject_uid;
    uint32_t subject_task;
    uint32_t object;
    uint32_t result;
    char     message[48];
};

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
/* 38-45: the legacy in-memory capfs. Removed — the syscalls fail closed and the
 * numbers are reserved (kept defined, not reused) so no future syscall silently
 * inherits an old capfs caller. The encrypted fs_server is the only filesystem. */
#define SYS_FS_MINT_FILE  38  /* reserved (removed) */
#define SYS_FS_LOOKUP     39  /* reserved (removed) */
#define SYS_FS_CREATE     40  /* reserved (removed) */
#define SYS_FS_DELETE     41  /* reserved (removed) */
#define SYS_FS_READDIR    42  /* reserved (removed) */
#define SYS_FS_GET_ROOT   43  /* reserved (removed) */
#define SYS_FS_READ       44  /* reserved (removed) */
#define SYS_FS_WRITE      45  /* reserved (removed) */
#define SYS_REGISTER_STORAGE_BACKEND 46
#define SYS_BLOCK_READ   47
#define SYS_BLOCK_WRITE  48
#define SYS_REGISTER_FS_SERVER 49
#define SYS_CONNECT_FS_SERVER  50
#define SYS_CAP_REVOKE         51
#define SYS_AUDIT_DIGEST       52
#define SYS_PREEMPT_TRACE      53   /* PREEMPT_SELFTEST builds only; NOSYS otherwise */
#define SYS_SIGACTION          54
#define SYS_SIGRETURN          55

/* Encrypted object-store API for the userspace filesystem server (Phase 2).
 * These expose the kernel's persistent, encrypted inode/block store to a ring-3
 * FS server WITHOUT handing it key material — the AEAD stays in the kernel. The
 * server addresses storage by (inode, logical block) and builds all filesystem
 * semantics (names, directories, permissions) on top. Gated like the raw block
 * syscalls: CAP_BLOCK_DEV (slot 7) + uid 0. */
#define SYS_FS_INODE_ALLOC     56   /* (type) -> ino */
#define SYS_FS_INODE_FREE      57   /* (ino)  -> 0 */
#define SYS_FBLOCK_READ        58   /* (ino, block, buf) -> BLOCK_SIZE (decrypt+verify) */
#define SYS_FBLOCK_WRITE       59   /* (ino, block, buf, len) -> len (encrypt, fresh nonce) */
#define SYS_FS_STAT            60   /* (ino, struct fs_stat*) -> 0 */
#define SYS_FS_SET_SIZE        61   /* (ino, size) -> 0 (server owns logical file size) */
#define SYS_BRK                62   /* (addr) -> new break; addr=0 queries current break */
#define SYS_KILL               63   /* (tid) -> terminate task tid; needs a CAP_TCB cap to it */
#define SYS_EXEC_NAMED         64   /* (name) -> replace the caller's own image with a named embedded binary; does not return on success */
#define SYS_CAP_GRANT          65   /* (target_tid, src_slot, dest_slot) -> copy caller's cap into a supervised child's cspace slot */
#define SYS_SIGNAL             66   /* (target_tid, signum) -> deliver a signal to a task held via CAP_TCB */
#define SYS_SIGMASK            67   /* (how, mask) -> old mask; block/unblock this task's own signals */
#define SYS_SPAWN_ARG          68   /* () -> the one-word argument this task was spawned with */
#define SYS_GET_ARGV           69   /* (char ***out) -> argc; writes the argv[] base to *out */
#define SYS_SPAWN_IMAGE        70   /* (image, len, arg, argv, argc) -> pid; spawn a child from a caller-supplied program image (execve-from-fd) */
#define SYS_EXEC_IMAGE         71   /* (image, len, 0, argv, argc) -> replace the caller's own image with a caller-supplied one; no return on success */
#define SYS_SIGALTSTACK        72   /* (ss_sp, ss_size) -> 0; register this task's alternate signal stack (ss_size 0 disables) */
#define SYS_IPC_SENDER         73   /* (ep, uint32_t *out_gid) -> uid; kernel-attested identity of an endpoint's last sender */
#define SYS_FS_SET_META        74   /* (ino, mode, uid, gid) -> 0; persist an inode's owner/mode (fs server only) */
#define SYS_IPC_REPLY_TO       75   /* (req_ep, msg, len) -> 0; reply to the last sender on req_ep (multi-client safe routing) */
/* Ring-3 device-driver framework: bind a hardware IRQ to a notification slot so a
 * ring-3 driver services the device, while the kernel keeps the PIC/EOI. Both are
 * gated by a CAP_IRQ naming the exact line (checked in-handler). */
#define SYS_IRQ_REGISTER       76   /* (irq, notif_slot) -> 0; deliver `irq` as a notification, unmask the line */
#define SYS_IRQ_ACK            77   /* (irq) -> 0; re-unmask the line after the driver has serviced the device */

/* Signal numbers (1..31). A task registers a handler with sys_signal() (see
 * below); an unhandled signal terminates the target (default action). */
#define SIG_KILL                9   /* uncatchable: always terminates, never masked */
#define SIG_USR1               10
#define SIG_USR2               12
#define SIG_TERM               15

/* sys_sigmask() `how`: combine the supplied mask with the current blocked set. */
#define SIG_SETMASK             0   /* replace the blocked set */
#define SIG_BLOCK               1   /* add to the blocked set */
#define SIG_UNBLOCK             2   /* remove from the blocked set */

/* sys_sigaltstack(): smallest alternate signal stack the kernel accepts, and the
 * ss_size value that disables the altstack (run handlers on the interrupted
 * stack). Mirror of SIG_ALTSTACK_MIN in the kernel. */
#define SIGSTKSZ_MIN         2048
#define SS_DISABLE              0

/* Inode metadata returned by SYS_FS_STAT. Kept ABI-stable across kernel/user. */
struct fs_stat {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
};

/* Object types used by the FS server / SYS_FS_INODE_ALLOC. */
#define FS_TYPE_FILE 1
#define FS_TYPE_DIR  2

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

static inline uint32_t syscall(uint32_t num, uint32_t a, uint32_t b, uint32_t c) {
    uint32_t ret;
    asm volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(a), "c"(b), "d"(c)
        : "memory"
    );
    return ret;
}

/* Up to 5 register args (num, a..e); the kernel reads eax,ebx,ecx,edx,esi,edi.
 * Bind the high args directly to esi/edi with the "S"/"D" constraints rather
 * than moving them in and clobbering — the previous "r"-operand form ran the
 * 32-bit PIE register allocator out of registers (ebx is the GOT pointer, and
 * esi/edi were both operands and clobbers). `f` is accepted for source
 * compatibility but not passed (no sixth arg register in this ABI). */
static inline uint32_t syscall6(uint32_t num, uint32_t a, uint32_t b, uint32_t c,
                                 uint32_t d, uint32_t e, uint32_t f) {
    uint32_t ret;
    (void)f;
    asm volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e)
        : "memory"
    );
    return ret;
}

static inline void sys_yield(void) {
    syscall(SYS_YIELD, 0, 0, 0);
}

/* Register (handler != 0) or clear (handler == 0) this task's own fault-signal
 * handler. On a ring-3 fault the kernel enters the handler at ring 3 with the
 * signal number in ebx and the faulting address in ecx, instead of killing the
 * task. Returns 0 on success, -1 if the handler is not in the user code window. */
static inline int sys_signal(uint32_t handler) {
    return syscall(SYS_SIGACTION, handler, 0, 0);
}

/* Called from a handler to resume the exact pre-signal context. Does not return
 * to the handler on success (execution jumps back to the interrupted point). */
static inline void sys_sigreturn(void) {
    syscall(SYS_SIGRETURN, 0, 0, 0);
}

/* Block/unblock this task's own signals. `how` is SIG_SETMASK / SIG_BLOCK /
 * SIG_UNBLOCK; `mask` is a bitmask (bit N = signal N). A blocked signal that
 * arrives stays pending and is delivered once unblocked. SIG_KILL can never be
 * blocked. Returns the previous blocked mask. */
static inline uint32_t sys_sigmask(uint32_t how, uint32_t mask) {
    return syscall(SYS_SIGMASK, how, mask, 0);
}

static inline int sys_print(const char *s) {
    return syscall(SYS_PRINT, (uint32_t)s, 0, 0);
}

static inline void sys_exit(void) {
    syscall(SYS_EXIT, 0, 0, 0);
    for(;;);
}

static inline int sys_get_line(char *buf, size_t max) {
    return syscall(SYS_GET_LINE, (uint32_t)buf, max, 0);
}

static inline void *sys_sbrk(intptr_t increment) {
    return (void*)syscall(SYS_SBRK, (uint32_t)increment, 0, 0);
}

/* sys_brk(addr): set the program break to addr and return the new break.
 * If addr is NULL/0, returns the current break without changing it.
 * On failure (out of range) returns the unchanged current break — callers
 * should compare the return value to addr to detect failure, matching Linux. */
static inline void *sys_brk(void *addr) {
    return (void*)syscall(SYS_BRK, (uint32_t)(uintptr_t)addr, 0, 0);
}

static inline int sys_write(int fd, const void *buf, size_t len) {
    return syscall(SYS_WRITE, (uint32_t)fd, (uint32_t)buf, (uint32_t)len);
}

static inline int sys_read(int fd, void *buf, size_t len) {
    return syscall(SYS_READ, (uint32_t)fd, (uint32_t)buf, (uint32_t)len);
}

static inline int sys_open(const char* path) {
    return syscall(SYS_OPEN, (uint32_t)path, 0, 0);
}

static inline int sys_wait(int task_id) {
    return syscall(SYS_WAIT, (uint32_t)task_id, 0, 0);
}

/* Terminate task `tid`. Authorised by holding a CAP_TCB capability to the target
 * in the caller's cspace (spawners get one for each child), or CAP_USER (admin).
 * Returns 0 on success, negative on permission/argument error. */
static inline int sys_kill(int tid) {
    return syscall(SYS_KILL, (uint32_t)tid, 0, 0);
}

static inline int sys_get_task_info(int id, struct task_info *out) {
    return syscall(SYS_GET_TASK_INFO, (uint32_t)id, (uint32_t)out, 0);
}

static inline int sys_exec(uint32_t load_base, uint32_t entry) {
    return syscall(SYS_EXEC, load_base, entry, 0);
}

static inline int sys_getpid(void) {
    return syscall(SYS_GETPID, 0, 0, 0);
}

static inline int sys_ipc_send(int ep_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_SEND, (uint32_t)ep_slot, (uint32_t)msg, (uint32_t)len);
}

static inline int sys_ipc_recv(int ep_slot, void *msg, size_t max_len) {
    return syscall(SYS_IPC_RECV, (uint32_t)ep_slot, (uint32_t)msg, (uint32_t)max_len);
}

/* Blocking send-then-receive: sends to send_ep, blocks until a message arrives
 * on reply_ep, copies at most IPC_MSG_MAX bytes into rbuf.  Returns the number
 * of bytes received, or a negative error code.
 * Uses EBX=send_ep, ECX=reply_ep, EDX=msg, ESI=len, EDI=rbuf (5 data args,
 * no EBP needed so -fno-omit-frame-pointer builds are safe). */
static inline int sys_ipc_call(int send_ep, int reply_ep,
                               const void *msg, uint32_t len,
                               void *rbuf) {
    uint32_t ret;
    asm volatile("int $0x80"
                 : "=a"(ret)
                 : "a"((uint32_t)SYS_IPC_CALL),
                   "b"((uint32_t)send_ep),
                   "c"((uint32_t)reply_ep),
                   "d"((uint32_t)(uintptr_t)msg),
                   "S"(len),
                   "D"((uint32_t)(uintptr_t)rbuf)
                 : "memory");
    return (int)ret;
}

static inline int sys_ipc_reply(int ep_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_REPLY, (uint32_t)ep_slot, (uint32_t)msg, (uint32_t)len);
}

/* Reply to the task that sent the request most recently received on `req_ep`,
 * delivered directly to that client's blocked sys_ipc_call by kernel-recorded
 * identity (not via a shared reply endpoint) — so one server can serve concurrent
 * clients without their replies colliding. Returns 0 on delivery (or if the
 * client has gone). A negative return means "retry" (the client raced and hasn't
 * finished blocking yet); a server loops until it succeeds. */
static inline int sys_ipc_reply_to(int req_ep, const void *msg, size_t len) {
    return syscall(SYS_IPC_REPLY_TO, (uint32_t)req_ep, (uint32_t)(uintptr_t)msg, (uint32_t)len);
}

/* Kernel-attested identity of the task that last sent on endpoint `ep`: returns
 * its uid and (via *out_gid) gid, as fixed by that task's login. A client cannot
 * forge this — it is not read from the request — so a server uses it instead of
 * trusting any identity a client places in the message body. Returns
 * (uint32_t)-1 when there is no valid last sender. */
static inline uint32_t sys_ipc_sender(int ep, uint32_t *out_gid) {
    return syscall(SYS_IPC_SENDER, (uint32_t)ep, (uint32_t)(uintptr_t)out_gid, 0);
}

static inline int sys_notify(int notif_slot, uint32_t badge) {
    return syscall(SYS_NOTIFY, (uint32_t)notif_slot, badge, 0);
}

/* sys_wait_notify: block until a badge arrives on notif_slot (or return
 * immediately if one is already pending).  The kernel returns the accumulated
 * badge bits in EBX (written via frame->rbx in interrupt_handler64) so no
 * cross-address-space pointer copy is needed. */
static inline int sys_wait_notify(int notif_slot, uint32_t *out_badge) {
    uint32_t ret, badge;
    asm volatile("int $0x80"
                 : "=a"(ret), "=b"(badge)
                 : "a"((uint32_t)SYS_WAIT_NOTIFY), "b"((uint32_t)notif_slot)
                 : "ecx", "edx", "memory");
    if (out_badge) *out_badge = badge;
    return (int)ret;
}

/* Bind hardware IRQ `irq` to notification slot `notif_slot`. From then on the
 * kernel EOIs + masks the line and sends a notification (badge = 1<<irq); the
 * driver waits on the slot, services the device via its granted ports, then calls
 * sys_irq_ack(irq). Requires a CAP_IRQ naming `irq`. Returns 0 on success. */
static inline int sys_irq_register(int irq, int notif_slot) {
    return (int)syscall(SYS_IRQ_REGISTER, (uint32_t)irq, (uint32_t)notif_slot, 0);
}

/* Re-unmask IRQ `irq` after servicing the device (the kernel masked it on
 * delivery so it cannot re-fire until acked). Requires a CAP_IRQ naming `irq`. */
static inline int sys_irq_ack(int irq) {
    return (int)syscall(SYS_IRQ_ACK, (uint32_t)irq, 0, 0);
}

static inline int sys_receive_program(struct program_header *hdr_out) {
    return syscall(SYS_RECEIVE_PROGRAM, (uint32_t)hdr_out, 0, 0);
}

static inline int sys_spawn(void) {
    return syscall(SYS_SPAWN, 0, 0, 0);
}

/* Spawn a named embedded binary (hello, captest, fs_server, shell).
 * Returns the new task pid on success, negative on error. */
static inline int sys_spawn_named(const char *name) {
    uint32_t len = 0;
    while (name[len] && len < 31) len++;
    return (int)syscall(SYS_SPAWN, (uint32_t)(uintptr_t)name, len, 0);
}

/* Spawn a named binary, handing the child a one-word argument it can retrieve
 * with sys_spawn_arg(). A minimal parameter-passing channel (full argv is future
 * work); today it carries e.g. a task id for a supervisor/waiter child. */
static inline int sys_spawn_named_arg(const char *name, uint32_t arg) {
    uint32_t len = 0;
    while (name[len] && len < 31) len++;
    return (int)syscall(SYS_SPAWN, (uint32_t)(uintptr_t)name, len, arg);
}

/* Retrieve the one-word argument this task was spawned with (0 if none). */
static inline uint32_t sys_spawn_arg(void) {
    return syscall(SYS_SPAWN_ARG, 0, 0, 0);
}

/* Spawn a named binary, passing it a full argument vector. The kernel copies the
 * `argc` strings from argv[] onto the child's initial stack; the child reads them
 * back with sys_get_argv(). Up to 16 args / 512 bytes total (excess is refused).
 * Returns the child's task id, or negative on error. */
static inline int sys_spawn_named_argv(const char *name, int argc, char *const argv[]) {
    uint32_t len = 0;
    while (name[len] && len < 31) len++;
    return (int)syscall6(SYS_SPAWN, (uint32_t)(uintptr_t)name, len, 0,
                         (uint32_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Retrieve this task's argument vector. Writes the argv[] base pointer to
 * *out_argv (NULL-terminated array) and returns argc (0 and NULL if none). */
static inline int sys_get_argv(char ***out_argv) {
    char **argv = 0;
    int argc = (int)syscall(SYS_GET_ARGV, (uint32_t)(uintptr_t)&argv, 0, 0);
    if (out_argv) *out_argv = argv;
    return argc;
}

/* Replace the calling task's image with a named embedded binary (hello, captest,
 * fs_server, shell), keeping the same task id and cspace (capabilities survive
 * the exec, POSIX-style). On success this does not return — control resumes at
 * the new image's entry point. Returns a negative error only on failure (e.g.
 * unknown name), in which case the caller's image is left intact. */
static inline int sys_exec_named(const char *name) {
    uint32_t len = 0;
    while (name[len] && len < 31) len++;
    return (int)syscall(SYS_EXEC_NAMED, (uint32_t)(uintptr_t)name, len, 0);
}

/* Replace the caller's image with a named binary, passing it a full argument
 * vector (marshalled onto the fresh stack; read back with sys_get_argv). On
 * success does not return; a negative return means the exec failed and the
 * caller's image is intact. */
static inline int sys_exec_named_argv(const char *name, int argc, char *const argv[]) {
    uint32_t len = 0;
    while (name[len] && len < 31) len++;
    return (int)syscall6(SYS_EXEC_NAMED, (uint32_t)(uintptr_t)name, len, 0,
                         (uint32_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Spawn a child from a program image the caller supplies in its own memory
 * (execve-from-fd): read a file into `image` (len bytes) via the fs_server, then
 * call this. The image is a Horus `.bin` (44-byte header + payload) or a bare
 * ELF; the kernel validates it with the same loader a named binary uses. The
 * child is handed a full argv (marshalled onto its stack; read via
 * sys_get_argv). Returns the child pid, or a negative SYS_ERR_* (the caller is
 * unaffected on failure). Needs slot-3 WRITE|EXEC, like sys_spawn_named. */
static inline int sys_spawn_image(const void *image, uint32_t len, int argc, char *const argv[]) {
    return (int)syscall6(SYS_SPAWN_IMAGE, (uint32_t)(uintptr_t)image, len, 0,
                         (uint32_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* As sys_spawn_image but also hands the child a one-word argument (sys_spawn_arg). */
static inline int sys_spawn_image_arg(const void *image, uint32_t len, uint32_t arg,
                                      int argc, char *const argv[]) {
    return (int)syscall6(SYS_SPAWN_IMAGE, (uint32_t)(uintptr_t)image, len, arg,
                         (uint32_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Replace the caller's own image with a caller-supplied program image
 * (execve-from-fd, in place), keeping the same task id and cspace (capabilities
 * survive, POSIX-style). On success this does not return — control resumes at the
 * new image's entry. A negative return means the image was rejected and the
 * caller's image is intact. Needs slot-3 WRITE|EXEC. */
static inline int sys_exec_image(const void *image, uint32_t len, int argc, char *const argv[]) {
    return (int)syscall6(SYS_EXEC_IMAGE, (uint32_t)(uintptr_t)image, len, 0,
                         (uint32_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Register this task's alternate signal stack: signals delivered while the task
 * is not already running on it enter the handler on [ss_sp, ss_sp+ss_size)
 * instead of the interrupted stack. Pass ss_size == SS_DISABLE to turn it off.
 * ss_size must be >= SIGSTKSZ_MIN and the range must lie inside the user address
 * space. Returns 0 on success, negative on error (bad range, or called while a
 * handler is running on the altstack). */
static inline int sys_sigaltstack(void *ss_sp, uint32_t ss_size) {
    return syscall(SYS_SIGALTSTACK, (uint32_t)(uintptr_t)ss_sp, ss_size, 0);
}

/* Delegate a capability to a child task: copy the caller's capability at
 * `src_slot` into `target_tid`'s cspace at `dest_slot`, with a fresh serial so
 * the grantee's cap_lookup accepts it. Authorised only if the caller holds a
 * CAP_TCB to `target_tid` (the per-child cap a spawner receives) or CAP_USER
 * admin — a task may only push capabilities down into children it supervises.
 * Returns 0 on success, negative on error (unauthorised, bad slot/target, or no
 * capability at src_slot). */
static inline int sys_cap_grant(int target_tid, uint32_t src_slot, uint32_t dest_slot) {
    return (int)syscall(SYS_CAP_GRANT, (uint32_t)target_tid, src_slot, dest_slot);
}

/* Send signal `signum` (1..31) to task `target_tid`, which the caller must hold a
 * CAP_TCB for (or be admin). If the target registered a handler (sys_signal), it
 * is redirected into it on its next return to ring 3 with `signum` in ebx;
 * otherwise the target is terminated (default action). Returns 0 on success,
 * negative on error (no capability, bad target/signum). */
static inline int sys_send_signal(int target_tid, uint32_t signum) {
    return (int)syscall(SYS_SIGNAL, (uint32_t)target_tid, signum, 0);
}

static inline uint32_t sys_getuid(void) {
    return syscall(SYS_GETUID, 0, 0, 0);
}

static inline int sys_auth(const char *user, const char *pass, uint32_t *out_uid) {
    return syscall(SYS_AUTH, (uint32_t)user, (uint32_t)pass, (uint32_t)out_uid);
}

static inline int sys_sudo(const char *pass) {
    return syscall(SYS_SUDO, (uint32_t)pass, 0, 0);
}

static inline int sys_get_pass(char *buf, size_t max) {
    return syscall(SYS_GET_PASS, (uint32_t)buf, max, 0);
}

static inline int sys_useradd(uint32_t uid, uint32_t gid, const char *name) {
    return syscall(SYS_USERADD, uid, gid, (uint32_t)name);
}

static inline int sys_userdel(uint32_t uid) {
    return syscall(SYS_USERDEL, uid, 0, 0);
}

static inline int sys_passwd(uint32_t target_uid, const char *newpass) {
    return syscall(SYS_PASSWD, target_uid, (uint32_t)newpass, 0);
}

static inline int sys_rotate_keys(void) {

    return syscall(SYS_ROTATE_KEYS, 0, 0, 0);
}

static inline int sys_read_audit(struct audit_event *events, uint32_t max_events) {
    return syscall(SYS_READ_AUDIT, (uint32_t)events, max_events, 0);
}

/* The legacy in-memory capfs userspace wrappers (sys_fs_mint_file / lookup /
 * create / delete / readdir / get_root / read / write, syscalls 38-45) were
 * removed along with the capfs engine; those syscalls now fail closed and the
 * encrypted fs_server is the only filesystem. The SYS_FS_* numbers stay defined
 * but reserved so they are not reused. */

/* sys_register_storage_backend() was removed: registering a userspace block
 * backend meant the kernel called ring-3 function pointers from ring 0 (an SMEP
 * violation and TCB escape). Syscall 46 now fails closed (SYS_ERR_NOSYS). The
 * #define is kept so the ABI slot stays reserved. */

static inline int sys_block_read(uint64_t block, void *buf, uint32_t len) {
    return (int)syscall6(SYS_BLOCK_READ, (uint32_t)(block >> 32), (uint32_t)block, (uint32_t)buf, len, 0, 0);
}

static inline int sys_block_write(uint64_t block, const void *buf, uint32_t len) {
    return (int)syscall6(SYS_BLOCK_WRITE, (uint32_t)(block >> 32), (uint32_t)block, (uint32_t)buf, len, 0, 0);
}

static inline int sys_register_fs_server(uint32_t ep_slot) {
    return syscall(SYS_REGISTER_FS_SERVER, ep_slot, 0, 0);
}

static inline int sys_connect_fs_server(uint32_t dest_slot, uint32_t rights) {
    return syscall(SYS_CONNECT_FS_SERVER, dest_slot, rights, 0);
}


static inline int sys_cap_revoke(uint32_t slot) {
    return syscall(SYS_CAP_REVOKE, slot, 0, 0);
}

/* --- Encrypted object-store API (used by the userspace FS server) ---------- */

/* Allocate a fresh inode of the given type (FS_TYPE_FILE / FS_TYPE_DIR).
 * Returns the inode number, or a negative SYS_ERR_*. */
static inline int sys_fs_inode_alloc(uint32_t type) {
    return syscall(SYS_FS_INODE_ALLOC, type, 0, 0);
}

/* Free an inode and all of its data blocks. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_inode_free(uint32_t ino) {
    return syscall(SYS_FS_INODE_FREE, ino, 0, 0);
}

/* Read logical `block` of `ino` (decrypt-and-verify in the kernel) into `buf`
 * (must hold BLOCK_SIZE=512 bytes). Returns bytes read (512) or a negative. */
static inline int sys_fblock_read(uint32_t ino, uint32_t block, void *buf) {
    return syscall(SYS_FBLOCK_READ, ino, block, (uint32_t)buf);
}

/* Write `len` (<=512) bytes to logical `block` of `ino` (kernel encrypts with a
 * fresh nonce); short writes are zero-padded to a full block. Returns len. */
static inline int sys_fblock_write(uint32_t ino, uint32_t block, const void *buf, uint32_t len) {
    return (int)syscall6(SYS_FBLOCK_WRITE, ino, block, (uint32_t)buf, len, 0, 0);
}

/* Fill *out with the inode's metadata. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_stat(uint32_t ino, struct fs_stat *out) {
    return syscall(SYS_FS_STAT, ino, (uint32_t)out, 0);
}

/* Set an inode's logical size (the FS server owns file size; the kernel only
 * stores fixed-size encrypted blocks). Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_set_size(uint32_t ino, uint32_t size) {
    return syscall(SYS_FS_SET_SIZE, ino, size, 0);
}

/* Persist an inode's permission bits (low 12 of `mode`) and owner (uid/gid).
 * Object-store server only (uid 0 + CAP_BLOCK_DEV); the file-type bits are
 * preserved. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_set_meta(uint32_t ino, uint32_t mode, uint32_t uid, uint32_t gid) {
    return (int)syscall6(SYS_FS_SET_META, ino, mode, uid, gid, 0, 0);
}

/* Audit-log integrity digest. Writes 40 bytes to `out` (8-byte little-endian
 * total event count, then the 32-byte chain head MAC) and returns the verify
 * status: 0 = retained window intact, >0 = (first tampered index + 1),
 * -1 = chain uninitialized, -3 = copy failed. Requires a CAP_AUDIT read cap. */
static inline int sys_audit_digest(void *out) {
    return syscall(SYS_AUDIT_DIGEST, (uint32_t)(unsigned long)out, 0, 0);
}

#endif
