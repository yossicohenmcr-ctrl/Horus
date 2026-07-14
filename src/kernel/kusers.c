/* kusers.c -- user accounts + authentication: the user DB, Argon2id password
 * hashing, salted verification, the encrypted userdb persistence, and the
 * auth/sudo/passwd/useradd/userdel/rotate-keys syscall handlers. Owns the
 * user table. Split out of syscall.c. */
#include "syscall_internal.h"

static struct user_account users[MAX_USERS];
static int user_count = 0;
static uint32_t next_uid = 1000;

uint8_t kernel_pepper[16];

static void generate_salt(uint8_t *salt, size_t len) {
    /* Per-password random salt drawn from the central CSPRNG (RDRAND/TSC-jitter
     * seeded), replacing the old predictable LCG-over-ticks generator. */
    secure_random_bytes(salt, len);
}

/* Password hash = Argon2id(password, salt || pepper), memory-hard.
 *
 * - Argon2id (RFC 9106) is the reviewed, memory-hard KDF, implemented in safe
 *   Rust (rust/src/argon2.rs) on the crate's own BLAKE2b and validated against
 *   the argon2-cffi reference vectors. It replaces PBKDF2-HMAC-SHA256: unlike
 *   PBKDF2, it forces an attacker to spend memory as well as time, defeating
 *   the cheap GPU/ASIC parallel brute force PBKDF2 is vulnerable to.
 * - The 16-byte per-boot kernel pepper is concatenated into the salt so an
 *   attacker who exfiltrates the user database alone still lacks a secret
 *   needed to mount an offline dictionary attack.
 * - The raw 32-byte tag is stored (PASS_HASH_LEN == 32), preserving full
 *   entropy. The 4 MiB scratch buffer is a kernel static; hashing runs
 *   non-preemptibly inside the syscall, so the single shared buffer is safe.
 */
static uint64_t argon2_scratch[ARGON2_M_COST_KIB * 128];

static void strong_password_hash(const char *password, const uint8_t *salt,
                                 const uint8_t *pepper, uint8_t *out_hash) {
    uint8_t combined_salt[PASS_SALT_LEN + 16];
    for (int i = 0; i < PASS_SALT_LEN; i++) combined_salt[i] = salt[i];
    for (int i = 0; i < 16; i++) combined_salt[PASS_SALT_LEN + i] = pepper[i];

    rust_argon2id_hash((const uint8_t *)password, kstrlen(password),
                       combined_salt, sizeof(combined_salt),
                       ARGON2_T_COST, ARGON2_M_COST_KIB, ARGON2_P_COST,
                       argon2_scratch, sizeof(argon2_scratch) / sizeof(argon2_scratch[0]),
                       out_hash, PASS_HASH_LEN);

    secure_zero(combined_salt, sizeof(combined_salt));
}

int kernel_argon2id(const uint8_t *pwd, size_t plen,
                    const uint8_t *salt, size_t salt_len,
                    uint8_t *out, size_t out_len)
{
    return rust_argon2id_hash(pwd, plen, salt, salt_len,
                              ARGON2_T_COST, ARGON2_M_COST_KIB, ARGON2_P_COST,
                              argon2_scratch,
                              sizeof(argon2_scratch) / sizeof(argon2_scratch[0]),
                              out, out_len);
}

static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
    }
    return diff == 0;
}

int set_user_password(uint32_t uid, const char *new_password) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            generate_salt(users[i].salt, PASS_SALT_LEN);
            strong_password_hash(new_password, users[i].salt, kernel_pepper,
                                 users[i].pass_hash);
            return 0;
        }
    }
    return -1;
}

static int verify_user_password(const char *name, const char *password) {
    struct user_account *u = NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            int match = 1;
            for (size_t j = 0; j < 32 && name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match && name[kstrlen(users[i].name)] == 0) {
                u = &users[i];
                break;
            }
        }
    }
    /* Run the same work whether or not the account exists, to deny an attacker
     * a timing oracle for username enumeration: always derive the (deliberately
     * expensive) Argon2id hash and run a constant-time compare. When the user is
     * absent we hash against a zero salt and compare the result against itself,
     * then discard the (necessarily "equal") outcome and fail. */
    static const uint8_t dummy_salt[PASS_SALT_LEN]; /* zero-initialized */
    uint8_t computed[PASS_HASH_LEN];
    const uint8_t *salt   = u ? u->salt      : dummy_salt;
    const uint8_t *expect = u ? u->pass_hash : computed;

    strong_password_hash(password, salt, kernel_pepper, computed);
    int eq = constant_time_compare(computed, expect, PASS_HASH_LEN);
    return (u && eq) ? 1 : 0;
}

#define USERDB_MAGIC 0x55534442
#define USERDB_TAG_LEN 32

/* Integrity tag over the user database = HMAC-SHA256(kernel_pepper, records).
 * Replaces the previous custom ARX construction. Valid records are serialized
 * in slot order into a fixed scratch buffer (matching the on-disk layout) and
 * authenticated as a single message. */
static void compute_userdb_tag(uint8_t *tag_out) {
    static uint8_t scratch[MAX_USERS * sizeof(struct user_account)];
    size_t off = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) continue;
        const uint8_t *rec = (const uint8_t *)&users[i];
        for (size_t j = 0; j < sizeof(struct user_account); j++) {
            scratch[off + j] = rec[j];
        }
        off += sizeof(struct user_account);
    }
    rust_hmac_sha256(kernel_pepper, sizeof(kernel_pepper), scratch, off, tag_out);
}

static int userdb_tag_valid(const uint8_t *tag_on_disk) {
    uint8_t computed[USERDB_TAG_LEN];
    compute_userdb_tag(computed);
    return constant_time_compare(computed, tag_on_disk, USERDB_TAG_LEN);
}

static void users_save_to_ramfs(void) {
    int fd = ramfs_open("passwd",0);
    if (fd < 0) {
        fd = ramfs_create("passwd",0);
        if (fd < 0) return;
    }

    uint32_t magic = USERDB_MAGIC;
    uint32_t count = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) count++;
    }

    ramfs_write(fd, &magic, sizeof(magic));
    ramfs_write(fd, &count, sizeof(count));

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            ramfs_write(fd, &users[i], sizeof(struct user_account));
        }
    }

    uint8_t tag[USERDB_TAG_LEN];
    compute_userdb_tag(tag);
    ramfs_write(fd, tag, USERDB_TAG_LEN);
}

static void users_persist(void) {
    users_save_to_ramfs();
}

static void users_load_from_ramfs(void) {
    int fd = ramfs_open("passwd",0);
    if (fd < 0) return;

    uint32_t magic = 0;
    uint32_t count = 0;
    if (ramfs_read(fd, &magic, sizeof(magic)) != sizeof(magic) ||
        magic != USERDB_MAGIC) {
        return;
    }
    if (ramfs_read(fd, &count, sizeof(count)) != sizeof(count) ||
        count > MAX_USERS) {
        return;
    }

    for (int i = 0; i < MAX_USERS; i++) users[i].valid = 0;
    user_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        struct user_account tmp;
        if (ramfs_read(fd, &tmp, sizeof(tmp)) == sizeof(tmp)) {
            int slot = -1;
            for (int j = 0; j < MAX_USERS; j++) {
                if (!users[j].valid) { slot = j; break; }
                if (users[j].uid == tmp.uid) { slot = j; break; }
            }
            if (slot >= 0) {
                users[slot] = tmp;
                users[slot].valid = 1;
                user_count++;
                if (tmp.uid >= next_uid) next_uid = tmp.uid + 1;
            }
        }
    }

    uint8_t tag_on_disk[USERDB_TAG_LEN];
    if (ramfs_read(fd, tag_on_disk, USERDB_TAG_LEN) != USERDB_TAG_LEN ||
        !userdb_tag_valid(tag_on_disk)) {
        for (int i = 0; i < MAX_USERS; i++) users[i].valid = 0;
        user_count = 0;
        next_uid = 1000;
    }
}

void users_init(void) {
    for (int i = 0; i < MAX_USERS; i++) {
        users[i].valid = 0;
    }
    user_count = 0;
    next_uid = 1000;

    /* Per-boot secret pepper from the central CSPRNG (RDRAND/TSC-jitter seeded),
     * replacing the predictable LCG-over-ticks generator. */
    secure_random_bytes(kernel_pepper, sizeof(kernel_pepper));

    /* Seed the tamper-evident audit chain now that its key (the pepper) exists,
     * before any audit_log() can fire from a syscall. */
    audit_chain_start();

    users[0].uid = 0;
    users[0].gid = 0;
    kstrcpy(users[0].name, "root");
    kstrcpy(users[0].home, "/");
    kstrcpy(users[0].shell, "/bin/shell");
    users[0].auth_fail_count = 0;
    users[0].auth_lockout_until = 0;
    users[0].valid = 1;

    set_user_password(0, "rootpass");
    user_count = 1;

    users[1].uid = 1000;
    users[1].gid = 100;
    kstrcpy(users[1].name, "user");
    kstrcpy(users[1].home, "/home/user");
    kstrcpy(users[1].shell, "/bin/shell");
    users[1].auth_fail_count = 0;
    users[1].auth_lockout_until = 0;
    users[1].valid = 1;
    set_user_password(1000, "password");
    user_count = 2;

    users_load_from_ramfs();

    /* Find the "user" account in whichever state the database is in after
     * users_load_from_ramfs: it may have been loaded with a changed password,
     * or may not exist yet (first boot, or ramfs tampered and cleared). */
    int dev_idx = -1;
    for (int ii = 0; ii < MAX_USERS; ii++) {
        if (users[ii].valid && kstrcmp(users[ii].name, "user") == 0) { dev_idx = ii; break; }
    }
    if (dev_idx < 0) {
        /* Account missing: create it with the default password and persist so
         * subsequent boots pick up the correct (possibly later changed) password.
         * Only runs on first boot or after a corrupted ramfs wipes the database. */
        for (int ii = 0; ii < MAX_USERS; ii++) if (!users[ii].valid) { dev_idx = ii; break; }
        if (dev_idx >= 0) {
            users[dev_idx].uid = 1000;
            users[dev_idx].gid = 100;
            kstrcpy(users[dev_idx].name, "user");
            kstrcpy(users[dev_idx].home, "/home/user");
            users[dev_idx].auth_fail_count = 0;
            users[dev_idx].auth_lockout_until = 0;
            kstrcpy(users[dev_idx].shell, "/bin/shell");
            users[dev_idx].valid = 1;
            user_count = dev_idx + 1;
            /* Pass uid 1000, not the slot index — set_user_password searches by
             * uid, not by position, so passing dev_idx would silently fail. */
            set_user_password(1000, "password");
            users_persist();
        }
    }
    /* The old code had an unconditional set_user_password("password") here that
     * ran even when the account was loaded from ramfs with a changed password,
     * resetting it every reboot and making SYS_PASSWD useless for "user". */
}


static int current_user_is_admin(void) {

    struct capability *c = cap_lookup(6, CAP_RIGHT_ALL);
    if (c && c->type == CAP_USER) return 1;
    return tasks[get_current_task()].uid == 0;
}

int do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *initial_password) {
    if (!current_user_is_admin()) return -1;
    if (user_count >= MAX_USERS) return -2;
    if (kstrlen(name) == 0 || kstrlen(name) >= 32) return -3;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            if (users[i].uid == uid) return -4;
            if (kstrcmp(users[i].name, name) == 0) return -5;
        }
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) {
            users[i].uid = uid;
            users[i].gid = gid;
            kstrcpy(users[i].name, name);
            kstrcpy(users[i].home, "/home/");
            size_t hlen = kstrlen(users[i].home);
            kstrcpy(users[i].home + hlen, name);
            kstrcpy(users[i].shell, "/bin/shell");
            users[i].auth_fail_count = 0;
            users[i].auth_lockout_until = 0;
            if (initial_password && *initial_password) {
                set_user_password(uid, initial_password);
            } else {
                /* No initial password supplied: lock the account by storing random
                 * bytes in pass_hash. Argon2id output is pseudorandom but derived
                 * from (password, salt, pepper) — storing arbitrary random bytes
                 * means no password can ever produce a match, so the account is
                 * inaccessible until an explicit SYS_PASSWD call sets a real hash.
                 * This closes the window where `useradd name` (empty password)
                 * followed by a crash or kill left a live account anyone could
                 * authenticate to with "". */
                generate_salt(users[i].salt, PASS_SALT_LEN);
                secure_random_bytes(users[i].pass_hash, PASS_HASH_LEN);
            }
            users[i].valid = 1;
            user_count++;
            if (uid >= next_uid) next_uid = uid + 1;
            users_persist();
            audit_log(AUDIT_USER_MGMT, uid, 0, "useradd");
            return 0;
        }
    }
    return -6;
}

int do_userdel(uint32_t uid) {
    if (!current_user_is_admin()) return -1;
    if (uid == 0) return -2;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            users[i].valid = 0;
            user_count--;
            users_persist();
            return 0;
        }
    }
    return -3;
}

int do_passwd(uint32_t target_uid, const char *new_password) {
    uint32_t my_uid = tasks[get_current_task()].uid;
    int is_admin = current_user_is_admin();

    if (!is_admin && my_uid != target_uid) return -1;

    int rc = set_user_password(target_uid, new_password);
    if (rc != 0) return rc;
    users_persist();

    /* If the user is changing their own password, re-wrap disk_key with the
     * new KEK so storage_unlock(new_password) succeeds on the next boot.
     * Without this, the on-disk wrapped key would still require the old
     * password and storage would be permanently locked after a reboot. */
    if (target_uid == my_uid)
        storage_rekey(new_password, kstrlen(new_password));

    return 0;
}


static struct user_account *find_user_by_name(const char *name) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && kstrlen(users[i].name) == kstrlen(name)) {
            int match = 1;
            for (size_t j = 0; name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match) return &users[i];
        }
    }
    return NULL;
}

static int verify_password(const char *name, const char *pass) {
    return verify_user_password(name, pass);
}



void h_auth(struct regs *r) {
    uint32_t now = get_system_ticks();

    char uname[32];
    char upass[32];
    if (copy_from_user(uname, (void*)(addr_t)r->ebx, 31) != 0 ||
        copy_from_user(upass, (void*)(addr_t)r->ecx, 31) != 0) {
        r->eax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    uname[31] = 0;
    upass[31] = 0;

    /* Global anti-spray cooldown: refuse all auth attempts kernel-wide
     * while it is active, so cycling usernames cannot dodge per-account
     * lockout. Policy + arithmetic live in rust/src/auth.rs. */
    if (rust_auth_global_locked(now)) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->eax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    struct user_account *u = find_user_by_name(uname);
    if (u && rust_auth_is_locked(u->auth_lockout_until, now)) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->eax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    if (verify_password(uname, upass)) {
        rust_auth_global_on_success();
        if (u) {
            u->auth_fail_count = 0;
            u->auth_lockout_until = 0;


            tasks[get_current_task()].uid = u->uid;
            tasks[get_current_task()].gid = u->gid;


            {
                char *mat = upass;
                size_t mlen = kstrlen(upass);
                derive_and_store_user_file_key(u->uid, mat, mlen);
                /* Unlock ATA storage (or format+seal on first boot).
                 * Uses the same password: same Argon2id input, different
                 * salt (kek_salt vs login salt||pepper) → independent keys. */
                storage_unlock(mat, mlen);
            }

            if (r->edx) {
                uint32_t uid = u->uid;
                copy_to_user((void*)(addr_t)r->edx, &uid, sizeof(uid));
            }
            audit_log(AUDIT_AUTH, 0, 0, "login success");
        }
        r->eax = 0;
    } else {
        rust_auth_global_on_failure(now);
        if (u) {
            uint32_t new_count = u->auth_fail_count;
            uint64_t new_lockout = 0;
            rust_auth_on_failure(u->auth_fail_count, now, &new_count, &new_lockout);
            u->auth_fail_count = new_count;
            if (new_lockout) u->auth_lockout_until = (uint32_t)new_lockout;
        }
        audit_log(AUDIT_AUTH, 0, -1, "login failure");
        r->eax = (uint32_t)SYS_ERR_AUTH;
    }
    /* Don't leave the cleartext password (and username) sitting in the
     * kernel stack frame after authentication completes. */
    secure_zero(uname, sizeof(uname));
    secure_zero(upass, sizeof(upass));
}

/* SYS_SUDO: re-auth the current user, then spawn an armed program as uid 0. */
void h_sudo(struct regs *r) {
    uint32_t now = get_system_ticks();
    struct user_account *cur_user = NULL;
    uint32_t cur_uid = tasks[get_current_task()].uid;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == cur_uid) {
            cur_user = &users[i];
            break;
        }
    }
    if (rust_auth_global_locked(now)) {
        r->eax = (uint32_t)SYS_ERR_AUTH;
        return;
    }
    if (cur_user && rust_auth_is_locked(cur_user->auth_lockout_until, now)) {
        r->eax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    char upass[32];
    if (copy_from_user(upass, (void*)(addr_t)r->ebx, 31) != 0) {
        secure_zero(upass, sizeof(upass));
        r->eax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    upass[31] = 0;

    struct user_account *cur = cur_user;
    if (!cur) {
        uint32_t cur_uid2 = tasks[get_current_task()].uid;
        for (int i = 0; i < MAX_USERS; i++) {
            if (users[i].valid && users[i].uid == cur_uid2) {
                cur = &users[i];
                break;
            }
        }
    }
    if (!cur) {
        secure_zero(upass, sizeof(upass));
        r->eax = (uint32_t)SYS_ERR_NOENT;
        return;
    }

    if (!verify_password(cur->name, upass)) {
        rust_auth_global_on_failure(now);
        if (cur_user) {
            uint32_t new_count = cur_user->auth_fail_count;
            uint64_t new_lockout = 0;
            rust_auth_on_failure(cur_user->auth_fail_count, now, &new_count, &new_lockout);
            cur_user->auth_fail_count = new_count;
            if (new_lockout) cur_user->auth_lockout_until = (uint32_t)new_lockout;
        }
        secure_zero(upass, sizeof(upass));
        r->eax = (uint32_t)SYS_ERR_AUTH;
        return;
    }
    rust_auth_global_on_success();
    if (cur_user) {
        cur_user->auth_fail_count = 0;
        cur_user->auth_lockout_until = 0;
    }


    {
        char *mat = upass;
        size_t mlen = kstrlen(upass);
        derive_and_store_user_file_key(cur->uid, mat, mlen);

    }
    /* Password material is no longer needed past key derivation; clear it
     * from the kernel stack frame on every remaining exit path. */
    secure_zero(upass, sizeof(upass));
    audit_log(AUDIT_SUDO, 0, 0, "sudo success");

    if (!program_armed) {
        r->eax = (uint32_t)SYS_ERR_INVAL;
        return;
    }

    int pid = do_spawn();
    if (pid > 0) {
        tasks[pid].uid = 0;
        tasks[pid].gid = 0;

        /* Allocate the three fresh serials BEFORE taking cap_lock:
         * cap_alloc_fresh_serial() grabs cap_lock itself and the lock
         * is not recursive, so calling it inside the locked region
         * (as this path previously did) deadlocks the kernel on the
         * first sudo. Same ordering do_spawn uses. */
        uint32_t s3 = cap_alloc_fresh_serial();
        uint32_t s6 = cap_alloc_fresh_serial();
        uint32_t s7 = cap_alloc_fresh_serial();

        spin_lock(&cap_lock);
        tasks[pid].cspace[3].type   = CAP_FRAME;
        /* Least privilege: a memory frame needs only read/write/execute,
         * not the mint/revoke/grant/audit bits CAP_RIGHT_ALL carried.
         * Mask comes from rust/src/auth.rs (single source of truth). */
        tasks[pid].cspace[3].rights = rust_sudo_frame_rights();
        tasks[pid].cspace[3].object = USER_VIRT_BASE;
        tasks[pid].cspace[3].badge  = 0;
        tasks[pid].cspace[3].serial = s3;
        tasks[pid].cspace[3].generation = 0;
        tasks[pid].cspace[3].parent = 0;   /* primordial re-provision: clear any stale lineage link (I2) */

        tasks[pid].cspace[6].type   = CAP_USER;
        tasks[pid].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[pid].cspace[6].object = 0;
        tasks[pid].cspace[6].badge  = 0xC0DE0006U;
        tasks[pid].cspace[6].serial = s6;
        tasks[pid].cspace[6].generation = 0;
        tasks[pid].cspace[6].parent = 0;

        tasks[pid].cspace[7].type   = CAP_TCB;
        tasks[pid].cspace[7].rights = CAP_RIGHT_ALL;
        tasks[pid].cspace[7].object = pid;
        tasks[pid].cspace[7].badge  = 0;
        tasks[pid].cspace[7].serial = s7;
        tasks[pid].cspace[7].generation = 0;
        tasks[pid].cspace[7].parent = 0;
        spin_unlock(&cap_lock);
    }
    r->eax = pid;
}

/* SYS_GET_PASS: read a line with masked echo; scrubs the scratch buffer. */
void h_get_pass(struct regs *r) {
    void *user_buf = (void *)(addr_t)r->ebx;
    uint32_t max_len = r->ecx;
    if (max_len > 127) max_len = 127;

    char line[128];
    uint32_t len = 0;
    char ch;

    while (len < max_len) {
        ch = console_getc();

        if (ch == '\r' || ch == '\n') {
            print("\n");
            break;
        }
        if (ch == '\b' || ch == 0x7F) {
            if (len > 0) { len--; print("\b \b"); }
            continue;
        }
        if ((unsigned char)ch < 32) continue;

        print("*");
        line[len++] = ch;
    }
    line[len] = 0;

    if (copy_to_user(user_buf, line, len + 1) != 0) {
        for (uint32_t i = 0; i < 128; i++) line[i] = 0;
        r->eax = -1;
        return;
    }

    for (uint32_t i = 0; i < 128; i++) line[i] = 0;

    r->eax = len;
}

/* SYS_READ_AUDIT: copy the audit ring buffer to userspace.
 * Capability (slot 7, READ, type CAP_AUDIT) is enforced centrally by the table. */

void h_useradd(struct regs *r) {
    uint32_t uid = r->ebx;
    uint32_t gid = r->ecx;
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->edx, 31) != 0) {
        r->eax = -1; return;
    }
    name[31] = 0;
    r->eax = do_useradd(uid, gid, name, "");
}
void h_userdel(struct regs *r) {
    r->eax = do_userdel(r->ebx);
}
void h_passwd(struct regs *r) {
    uint32_t target = r->ebx;
    char newpass[32];
    if (copy_from_user(newpass, (void*)(addr_t)r->ecx, 31) != 0) {
        r->eax = -1; return;
    }
    newpass[31] = 0;
    r->eax = do_passwd(target, newpass);
    secure_zero(newpass, sizeof(newpass));
}

/* SYS_ROTATE_KEYS (36): slot-8 READ, type CAP_CONSOLE enforced by the table. */
void h_rotate_keys(struct regs *r) {
    r->eax = (uint32_t)do_rotate_keys();
}

/* FS ops (38-45): authority is the per-call dir/file capability, checked inside
 * the sys_fs_* helpers (slot is an argument, so not table-expressible). */

