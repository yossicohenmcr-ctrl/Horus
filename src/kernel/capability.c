#include "kernel.h"

/*
 * FFI layout contract — mirror of the compile-time assertions in
 * rust/src/capability.rs. capability_t and the Rust `Capability` struct are the
 * same memory passed across the FFI; if a field is reordered/retyped in either
 * language, one of these assertions fails to compile. Offsets are identical on
 * 32- and 64-bit; only trailing padding differs, so we assert offsets.
 */
_Static_assert(__builtin_offsetof(capability_t, type)       == 0,  "cap.type offset");
_Static_assert(__builtin_offsetof(capability_t, rights)     == 4,  "cap.rights offset");
_Static_assert(__builtin_offsetof(capability_t, object)     == 8,  "cap.object offset");
_Static_assert(__builtin_offsetof(capability_t, badge)      == 16, "cap.badge offset");
_Static_assert(__builtin_offsetof(capability_t, serial)     == 20, "cap.serial offset");
_Static_assert(__builtin_offsetof(capability_t, generation) == 24, "cap.generation offset");
_Static_assert(CAP_NULL == 0, "CAP_NULL must be 0 (matches Rust)");

extern tcb_t tasks[MAX_TASKS];

#define CNODE_SIZE 256
#define KERNEL_RESERVED_CAPS 4

static struct capability root_cnode[CNODE_SIZE];

static uint32_t cap_next_serial = 0x00010000U;

#define MAX_REV_SETS 8


uint32_t cap_alloc_fresh_serial(void) {
    /* Wrap logic lives once, in Rust (assign_fresh_serial); we only own the lock
     * and the counter here. Keeps C and Rust serial generation from drifting. */
    spin_lock(&cap_lock);
    uint32_t s = rust_cap_alloc_serial(&cap_next_serial);
    spin_unlock(&cap_lock);
    return s;
}

/*
 * Lineage / generation tracking is owned entirely by the safe-Rust authority
 * (rust/src/capability.rs, LINEAGE_GEN). The kernel previously kept a second,
 * independently-hashed `lineages[]` table here; the two could desync, letting a
 * stale derived capability pass one generation check while the other lineage had
 * already been bumped (use-after-revoke). The C table has been removed: every
 * bump goes through rust_lineage_bump (inside rust_cap_revoke / *_by_values) and
 * every check goes through rust_lineage_check via the thin wrapper below.
 */
bool capability_validate_generation(const capability_t *cap){
    if(!cap||cap->type==CAP_NULL) return false;
    return rust_lineage_check(cap->object, cap->generation);
}

static struct {
    uint32_t target_slot;
    uint32_t badge;
    int      valid;
} rev_sets[MAX_REV_SETS];

void cap_init(void) {
    for (int i = 0; i < CNODE_SIZE; i++) {
        root_cnode[i].type = CAP_NULL;
        root_cnode[i].rights = 0;
        root_cnode[i].object = 0;
        root_cnode[i].badge = 0;
        root_cnode[i].serial = 0;
    }
    root_cnode[0].type = CAP_TCB;
    root_cnode[0].rights = CAP_RIGHT_ALL;
    root_cnode[0].object = 0;
    root_cnode[0].badge = 0;
    root_cnode[0].serial = 0xC0DE0001U;
    root_cnode[0].generation = 0;

    root_cnode[1].type = CAP_NOTIFICATION;
    root_cnode[1].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[1].object = 0;
    root_cnode[1].badge = 0;
    root_cnode[1].serial = 0xC0DE0002U;
    root_cnode[1].generation = 0;

    root_cnode[2].type = CAP_ENDPOINT;
    root_cnode[2].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT;
    root_cnode[2].object = 0;
    root_cnode[2].badge = 0;
    root_cnode[2].serial = 0xC0DE0003U;
    root_cnode[2].generation = 0;

    root_cnode[3].type = CAP_FRAME;
    root_cnode[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    root_cnode[3].object = USER_VIRT_BASE;
    root_cnode[3].badge = 0;
    root_cnode[3].serial = 0xC0DE0004U;
    root_cnode[3].generation = 0;

    root_cnode[6].type   = CAP_USER;
    root_cnode[6].rights = CAP_RIGHT_ALL;
    root_cnode[6].object = 0;
    root_cnode[6].badge  = 0;
    root_cnode[6].serial = 0xC0DE0006U;
    root_cnode[6].generation = 0;

    root_cnode[7].type   = CAP_AUDIT;
    root_cnode[7].rights = CAP_RIGHT_READ | CAP_RIGHT_AUDIT_WRITE;
    root_cnode[7].object = 0;
    root_cnode[7].badge  = 0;
    root_cnode[7].serial = 0xC0DE0007U;
    root_cnode[7].generation = 0;

    
    root_cnode[8].type   = CAP_CONSOLE;
    root_cnode[8].rights = CAP_RIGHT_ALL;
    root_cnode[8].object = 0;
    root_cnode[8].badge  = 0;
    root_cnode[8].serial = 0xC0DE0008U;
    root_cnode[8].generation = 0;

    
    root_cnode[9].type   = CAP_ENCRYPTED_STORAGE;
    root_cnode[9].rights = CAP_RIGHT_ALL;
    root_cnode[9].object = 0;
    root_cnode[9].badge  = 0;
    root_cnode[9].serial = 0xC0DE0009U;
    root_cnode[9].generation = 0;

    cap_next_serial = 0x00010000U;

    for (int i = 0; i < MAX_REV_SETS; i++) rev_sets[i].valid = 0;
    /* Lineage generations live in the Rust authority (LINEAGE_GEN); nothing to
     * initialize here — it is zeroed in the static and bumped lazily. */
}

/* Install a copy of a primordial root capability into a task's cspace slot with
 * a fresh serial (so cap_lookup accepts it). Used to bootstrap the ring-3 init
 * process with the capabilities it delegates onward (spawn_initial_userspace_init)
 * and by the FS/process-control self-test harnesses; root_cnode is otherwise
 * file-private. */
int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object) {
    extern tcb_t tasks[MAX_TASKS];
    if (pid < 0 || pid >= MAX_TASKS || slot >= CNODE_SIZE || root_slot >= CNODE_SIZE) return -1;
    if (!tasks[pid].cspace) return -1;
    uint32_t serial = cap_alloc_fresh_serial();
    spin_lock(&cap_lock);
    tasks[pid].cspace[slot]            = root_cnode[root_slot];
    tasks[pid].cspace[slot].object     = object;
    tasks[pid].cspace[slot].serial     = serial;
    tasks[pid].cspace[slot].generation = 0;
    spin_unlock(&cap_lock);
    return 0;
}

/*
 * Resolve a capability slot for the current task, fail-closed.
 *
 * The root_cnode fallback is KERNEL-ONLY. Every non-kernel task resolves
 * strictly within its OWN cspace; a slot at or beyond the task's cspace size
 * returns NULL rather than silently falling through to root_cnode, which holds
 * admin authority (CAP_USER at slot 6, CAP_ENCRYPTED_STORAGE at slot 9). The
 * previous form (`cspace && slot < cspace_sz` else root_cnode) let ANY task with
 * a cspace smaller than the requested slot resolve that slot against root_cnode
 * — a latent ring-3 -> ring-0 escalation the instant a task is ever created with
 * cspace_size < CNODE_SIZE. Only the kernel boot task (id 0) legitimately has no
 * cspace and may reach root_cnode; this mirrors caller_has_authority()'s
 * no-ambient-authority guard for the mutating ops.
 */
struct capability *cap_lookup(uint32_t slot, uint32_t required_rights) {
    if (slot >= CNODE_SIZE) return NULL;

    int cur = get_current_task();
    if (cur < 0 || cur >= MAX_TASKS) return NULL;

    struct capability *cspace = tasks[cur].cspace;
    uint32_t cspace_sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
    struct capability *p;

    if (cspace) {
        /* Own cspace only — an out-of-range slot fails closed, never root_cnode. */
        if (slot >= cspace_sz) return NULL;
        p = rust_cap_lookup(cspace, cspace_sz, slot, required_rights);
    } else {
        /* A cspace-less task is the kernel boot task (id 0) or is missing its
         * cspace; only the former may resolve against the kernel root cnode. */
        if (cur != 0) return NULL;
        p = rust_cap_lookup(root_cnode, CNODE_SIZE, slot, required_rights);
    }

    if (p && !capability_validate_generation(p)) return NULL;
    return p;
}

void kassert_cap(struct capability *c){if(!c){for(;;){}}}
struct capability *kcap_lookup(uint32_t slot,uint32_t r){struct capability *c=cap_lookup(slot,r);kassert_cap(c);return c;}

/*
 * Capability snapshot + revalidation (defense-in-depth against lookup/use
 * TOCTOU). A looked-up `struct capability *` can become stale if any operation
 * between lookup and use yields, drops cap_lock, or (under future preemption)
 * is interrupted by another task that revokes or re-mints the slot. The pattern
 * is: snapshot at lookup, then `cap_revalidate(slot, rights, &snap)` at the
 * point of use — it re-looks-up the slot and confirms it STILL holds the same
 * capability identity (serial, generation, object) with the required rights.
 * A mismatch (revoked, replaced, or generation-bumped) returns NULL.
 *
 * "Validate at use" beats "look up once": the returned pointer is only trusted
 * for the instant it is reconfirmed under the same invariants cap_lookup
 * enforces (rights mask + Rust lineage/generation check).
 */
cap_snapshot_t cap_snapshot(const struct capability *c) {
    cap_snapshot_t s;
    if (c) {
        s.serial = c->serial;
        s.generation = c->generation;
        s.object = c->object;
        s.valid = (c->type != CAP_NULL);
    } else {
        s.serial = 0; s.generation = 0; s.object = 0; s.valid = 0;
    }
    return s;
}

struct capability *cap_revalidate(uint32_t slot, uint32_t required_rights,
                                  const cap_snapshot_t *snap) {
    if (!snap || !snap->valid) return NULL;
    struct capability *p = cap_lookup(slot, required_rights);
    if (!p) return NULL;
    /* Identity must be unchanged: a revoke nulls these, a re-mint changes the
     * serial, and a lineage revocation bumps the generation. */
    if (p->serial != snap->serial ||
        p->generation != snap->generation ||
        p->object != snap->object) {
        return NULL;
    }
    return p;
}

/*
 * No ambient authority. Every non-kernel task must act within its OWN cspace.
 * Only the kernel boot task (id 0) legitimately operates on root_cnode — user
 * task ids are always >= 1 (allocated from 1 in do_spawn) and are given a real
 * cspace at create_task time. Any other task that reaches the root_cnode
 * fallback is missing its cspace, so refuse it rather than grant it kernel
 * trust. This makes the "cspace == root_cnode" rights-check exemption in the
 * mutating ops below provably mean "kernel only", closing the escalation path
 * where a cspace-less task could mint/transfer/revoke without holding the right.
 */
static bool caller_has_authority(void) {
    int cur = get_current_task();
    return cur == 0 || tasks[cur].cspace != NULL;
}

bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights) {
    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }
    struct capability *src = kcap_lookup(src_slot, CAP_RIGHT_MINT);
    if (!src || dest_slot >= CNODE_SIZE) {
        spin_unlock(&cap_lock);
        return false;
    }

    if (dest_slot < KERNEL_RESERVED_CAPS) {
        spin_unlock(&cap_lock);
        return false;
    }

    struct capability *dest_array = tasks[get_current_task()].cspace
        ? tasks[get_current_task()].cspace
        : root_cnode;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size
        ? tasks[get_current_task()].cspace_size
        : CNODE_SIZE;

    
    bool was_null = (dest_array[dest_slot].type == CAP_NULL);
    if (was_null) {
        if (tasks[get_current_task()].caps_in_use >= MAX_CAPS_PER_TASK) {
            spin_unlock(&cap_lock);
            return false;
        }
    }

    
    bool ok = rust_cap_mint(dest_array, cspace_sz, dest_slot, src_slot, new_rights,
                            &cap_next_serial,
                            tasks[get_current_task()].caps_in_use);
    if (ok && was_null) {
        tasks[get_current_task()].caps_in_use++;
    }

    /* No separate C lineage registration: rust_cap_mint already records the
     * minted capability's generation as the floor in the Rust LINEAGE_GEN
     * authority, so the C side has nothing to track. */

    spin_unlock(&cap_lock);
    return ok;
}

bool cap_transfer(uint32_t dest_slot, uint32_t src_slot) {
    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }
    struct capability *src = kcap_lookup(src_slot, CAP_RIGHT_MINT);
    if (!src || dest_slot >= CNODE_SIZE) {
        spin_unlock(&cap_lock);
        return false;
    }
    if (dest_slot < KERNEL_RESERVED_CAPS) {
        spin_unlock(&cap_lock);
        return false;
    }

    struct capability *dest_array = tasks[get_current_task()].cspace
        ? tasks[get_current_task()].cspace
        : root_cnode;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size
        ? tasks[get_current_task()].cspace_size
        : CNODE_SIZE;

    bool was_null = (dest_array[dest_slot].type == CAP_NULL);
    if (was_null && tasks[get_current_task()].caps_in_use >= MAX_CAPS_PER_TASK) {
        spin_unlock(&cap_lock);
        return false;
    }

    bool ok = rust_cap_transfer(dest_array, cspace_sz, dest_slot, src_slot, &cap_next_serial);
    if (ok && was_null) {
        tasks[get_current_task()].caps_in_use++;
    }
    spin_unlock(&cap_lock);
    return ok;
}

bool cap_move(uint32_t dest_slot, uint32_t src_slot) {
    if (cap_transfer(dest_slot, src_slot)) {
        return cap_revoke(src_slot);
    }
    return false;
}

bool cap_revoke(uint32_t slot) {
    spin_lock(&cap_lock);
    if (slot >= CNODE_SIZE) {
        spin_unlock(&cap_lock);
        return false;
    }
    if (!caller_has_authority()) {
        spin_unlock(&cap_lock);
        return false;
    }
    struct capability *cspace = tasks[get_current_task()].cspace ? tasks[get_current_task()].cspace : root_cnode;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size ? tasks[get_current_task()].cspace_size : CNODE_SIZE;
    if (slot < KERNEL_RESERVED_CAPS && cspace == root_cnode) {
        spin_unlock(&cap_lock);
        return false;
    }
    if ((cspace[slot].rights & CAP_RIGHT_REVOKE) == 0 && cspace != root_cnode) {
        spin_unlock(&cap_lock);
        return false;
    }
    uint32_t orig_type = cspace[slot].type;

    /* Revocation-set indirection: a CAP_REVOCATION capability names a target
     * slot in `object`. Revoke the helper slot itself (single cspace), then
     * redirect to the real target before the system-wide sweep. */
    if (orig_type == CAP_REVOCATION && cspace[slot].object < CNODE_SIZE) {
        uint32_t real_target = (uint32_t)cspace[slot].object;
        rust_cap_revoke(cspace, cspace_sz, slot, &cap_next_serial);
        slot = real_target;
        if (slot >= CNODE_SIZE) {
            spin_unlock(&cap_lock);
            return true;
        }
    }

    /* Snapshot serial/badge for the rev_sets cleanup below, before the slot is
     * nulled by the revocation. */
    uint32_t target_serial = cspace[slot].serial;
    uint32_t target_badge = cspace[slot].badge;

    /*
     * INVARIANT (ARCHITECTURE.md): revocation is system-wide. We hand the Rust
     * authority every live task's cspace plus the kernel root cnode, and it
     * nulls the target plus every derived copy of the same lineage in ANY of
     * them, bumping the lineage generation exactly once. This closes the
     * use-after-revoke / privilege-retention hole where a derived capability in
     * another task's CNode could outlive its parent. The whole sweep runs under
     * cap_lock so the snapshot of tasks[] is stable.
     */
    cspace_desc_t spaces[MAX_TASKS + 1];
    uint32_t nspaces = 0;
    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0 || !tasks[t].cspace) continue;
        spaces[nspaces].caps = tasks[t].cspace;
        spaces[nspaces].size = tasks[t].cspace_size ? tasks[t].cspace_size : CNODE_SIZE;
        spaces[nspaces].caps_in_use = &tasks[t].caps_in_use;
        nspaces++;
    }
    /* The kernel root cnode is not any task's cspace; include it so kernel-held
     * derived copies are swept too. (No task uses root_cnode as its cspace, so
     * this cannot double-count.) */
    spaces[nspaces].caps = root_cnode;
    spaces[nspaces].size = CNODE_SIZE;
    spaces[nspaces].caps_in_use = NULL;
    nspaces++;

    /* The target's own caps_in_use counter (NULL when revoking in root_cnode). */
    uint32_t *target_ciu = (cspace == root_cnode) ? NULL : &tasks[get_current_task()].caps_in_use;

    bool ok = rust_cap_revoke_global(cspace, cspace_sz, slot, target_ciu,
                                     spaces, nspaces, &cap_next_serial);

    for (int r = 0; r < MAX_REV_SETS; r++) {
        if (rev_sets[r].valid &&
            (rev_sets[r].badge == target_badge || rev_sets[r].badge == slot ||
             (target_serial != 0 && rev_sets[r].badge == target_serial))) {
            rev_sets[r].valid = 0;
        }
    }
    spin_unlock(&cap_lock);
    return ok;
}

bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot) {
    /* Mutates the caller's cspace, so it must observe the same discipline as
     * cap_mint/cap_transfer/cap_revoke: hold cap_lock for the read-modify-write
     * and require authority (so the root_cnode fallback is provably kernel-only
     * for any cspace-less task). Currently has no callers, but is exported in
     * kernel.h -- harden it now so wiring it to a syscall later is not a hole. */
    /* Allocate the serial before taking cap_lock: cap_alloc_fresh_serial()
     * grabs cap_lock itself and the lock is not recursive (same ordering
     * do_spawn uses). A serial burned on a later validation failure is
     * harmless -- the counter is monotonic. */
    uint32_t fresh_serial = cap_alloc_fresh_serial();

    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }

    struct capability *cspace = tasks[get_current_task()].cspace ? tasks[get_current_task()].cspace : root_cnode;

    if (target_slot >= CNODE_SIZE || rev_slot >= CNODE_SIZE || target_slot < 4) {
        spin_unlock(&cap_lock);
        return false;
    }

    struct capability *target = &cspace[target_slot];
    if (target->type == CAP_NULL) {
        spin_unlock(&cap_lock);
        return false;
    }

    cspace[rev_slot].type   = CAP_REVOCATION;
    cspace[rev_slot].rights = CAP_RIGHT_REVOKE;
    cspace[rev_slot].object = target_slot;
    cspace[rev_slot].badge  = 0xDEAD0000U;
    cspace[rev_slot].serial = fresh_serial;
    cspace[rev_slot].generation = 0;

    spin_unlock(&cap_lock);
    return true;
}

bool has_encrypted_storage_cap(void) {
    struct capability *c = cap_lookup(9, 0);
    return (c && c->type == CAP_ENCRYPTED_STORAGE);
}
