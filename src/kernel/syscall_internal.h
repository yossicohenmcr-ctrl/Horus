/* syscall_internal.h -- shared declarations for the syscall subsystem.
 *
 * syscall.c was split into cohesive translation units (kaudit.c, kusers.c,
 * loader.c, kspawn.c, syscall_ipc.c, syscall_fs.c, selftest.c, kshell.c) around
 * the central dispatch hub in syscall.c. This header carries the symbols that
 * genuinely cross those module boundaries: the loader staging state, the audit
 * event-type codes, the tiny freestanding string helpers, a handful of loader/
 * spawn helpers, and the prototypes of every syscall handler defined outside
 * syscall.c that the dispatch table (in syscall.c) still needs to reference.
 *
 * Everything else stays file-local (static) to its module.
 */
#ifndef HORUS_SYSCALL_INTERNAL_H
#define HORUS_SYSCALL_INTERNAL_H

#include "kernel.h"

/* ---- Loader staging state (defined in loader.c) -------------------------- *
 * The staging buffer + armed program header are shared by the loader, the
 * spawn/exec paths, the boot shell launcher, and the gated self-tests. */
#define MAX_PROGRAM_SIZE (1024 * 1024)
extern uint8_t loader_staging[MAX_PROGRAM_SIZE];
extern struct program_header armed_hdr;
extern int program_armed;

/* ---- Audit event-type codes (consumed by handlers across modules) -------- */
#ifndef AUDIT_AUTH
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

#define AUDIT_IPC_GRANT     30
#define AUDIT_TASK_CREATE   40
#define AUDIT_TASK_EXIT     41
#endif

/* ---- Minimal freestanding string helpers (were file-local to syscall.c) -- *
 * Kept as static inline so each translation unit gets its own copy with no
 * cross-TU linkage; unused ones produce no warning. */
static inline size_t kstrlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}
static inline void kstrcpy(char *dst, const char *src) {
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}
static inline int kstrcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
static inline int kstrncmp(const char *a, const char *b, size_t n) {
    while (n > 0 && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

/* Little-endian 32-bit read from an ELF byte image (loader + elf self-test). */
static inline uint32_t elf_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- Debug-shell command history (defined in kshell.c) ------------------- *
 * Shared between the SYS_GET_LINE handler's line editor (syscall.c) and the
 * command loop (kshell.c). DEBUG_SHELL builds only. */
#ifdef DEBUG_SHELL
#define HISTORY_SIZE 8
#define CMD_MAX 128
extern char cmd_history[HISTORY_SIZE][CMD_MAX];
extern int history_count;
extern int history_pos;
#endif

/* ---- Audit (defined in kaudit.c) ----------------------------------------- */
void audit_log(uint32_t type, uint32_t object, int32_t result, const char *msg);
void audit_chain_start(void);   /* seed the tamper-evident MAC chain (boot) */

/* ---- Dispatch-table descriptor sentinels (table lives in syscall.c) ------ *
 * slot == SC_NONE: no single fixed authorizing capability (the handler does
 * its own check). ctype == SC_ANYTYPE: any capability type accepted. */
#define SC_NONE     0xFFFFu
#define SC_ANYTYPE  (-1)

/* ---- Cross-module loader / spawn helpers --------------------------------- */
int  arm_named_binary(const char *name);                                   /* loader.c */
int  arm_image_from_user(uint32_t ubuf, uint32_t len, const char *name_hint); /* loader.c */
int  try_elf_load(uint32_t load_base, uint32_t *out_entry, uint32_t *out_img_end); /* loader.c */
void choose_image_placement(int tid, uint32_t *out_load_base, uint32_t *out_stack_top); /* loader.c */
void load_staged_image_into(int tid, uint32_t load_base);                  /* loader.c */
int  do_receive_program(struct program_header *hdr_out);                   /* loader.c */
int  do_spawn(void);                                                       /* kspawn.c */

/* ---- Syscall handlers defined outside syscall.c but wired into the ------- *
 * dispatch table there. Every one has the uniform handler signature. */
/* kaudit.c */
void h_read_audit(struct regs *r);
void h_audit_digest(struct regs *r);
/* kusers.c */
void h_auth(struct regs *r);
void h_sudo(struct regs *r);
void h_get_pass(struct regs *r);
void h_useradd(struct regs *r);
void h_userdel(struct regs *r);
void h_passwd(struct regs *r);
void h_rotate_keys(struct regs *r);
/* kspawn.c */
void h_exec_named(struct regs *r);
void h_exec_image(struct regs *r);
void h_spawn(struct regs *r);
void h_spawn_image(struct regs *r);
void h_spawn_arg(struct regs *r);
void h_get_argv(struct regs *r);
/* syscall_fs.c */
void h_fs_list(struct regs *r);
void h_open(struct regs *r);
void h_ramfs_create(struct regs *r);
void h_block_read(struct regs *r);
void h_block_write(struct regs *r);
void h_register_fs_server(struct regs *r);
void h_connect_fs_server(struct regs *r);
void h_fs_inode_alloc(struct regs *r);
void h_fs_inode_free(struct regs *r);
void h_fblock_read(struct regs *r);
void h_fblock_write(struct regs *r);
void h_fs_set_size(struct regs *r);
void h_fs_set_meta(struct regs *r);
void h_fs_stat(struct regs *r);
/* h_fs_mint_file / lookup / create / delete / readdir / get_root / read / write
 * (legacy capfs) removed — those syscall numbers fail closed. */
void h_register_storage_backend(struct regs *r);
/* syscall_ipc.c */
void h_ipc_send(struct regs *r);
void h_ipc_call(struct regs *r);
void h_ipc_recv(struct regs *r);
void h_ipc_reply(struct regs *r);
void h_ipc_sender(struct regs *r);
void h_ipc_reply_to(struct regs *r);
void h_notify(struct regs *r);
void h_wait_notify(struct regs *r);
void h_irq_register(struct regs *r);
void h_irq_ack(struct regs *r);
/* selftest.c (test-only trace hook) */
#ifdef PREEMPT_SELFTEST
void h_preempt_trace(struct regs *r);
#endif

#endif /* HORUS_SYSCALL_INTERNAL_H */
