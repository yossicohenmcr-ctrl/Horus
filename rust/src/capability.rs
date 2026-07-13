use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub typ: u32,
    pub rights: u32,
    pub object: u64,
    pub badge: u32,
    pub serial: u32,
    pub generation: u32,
}

pub const CAP_NULL: u32 = 0;

// ---------------------------------------------------------------------------
// FFI layout contract.
//
// `Capability` (Rust) and `capability_t` (src/include/kernel.h) MUST have the
// identical layout — the kernel passes raw `*mut Capability` across the FFI and
// both sides index the same memory. These compile-time assertions pin the field
// offsets so reordering or retyping a field in either language fails to build.
// The mirror image of these checks lives in src/kernel/capability.c as
// `_Static_assert`s. Field offsets are identical on the 32- and 64-bit targets;
// only the trailing padding (and thus size_of) differs, so we assert offsets,
// not size.
// ---------------------------------------------------------------------------
const _: () = {
    assert!(core::mem::offset_of!(Capability, typ) == 0);
    assert!(core::mem::offset_of!(Capability, rights) == 4);
    assert!(core::mem::offset_of!(Capability, object) == 8);
    assert!(core::mem::offset_of!(Capability, badge) == 16);
    assert!(core::mem::offset_of!(Capability, serial) == 20);
    assert!(core::mem::offset_of!(Capability, generation) == 24);
    assert!(CAP_NULL == 0);
};

const CNODE_SIZE: u32 = 256;
const KERNEL_RESERVED_CAPS: u32 = 4;
/// Mirror of `MAX_TASKS` in src/include/kernel.h. Only used to size the
/// revocation worklist below; kept in sync with the C constant.
const MAX_TASKS: usize = 64;


const MIN_DERIVED_SERIAL: u32 = 0x00010000;





// Single source of truth for per-object lineage generations.
//
// This table is the *authority* for revocation/use-after-revoke detection.
// The C side no longer keeps its own `lineages[]` table; it delegates every
// generation check and bump through the `rust_lineage_check` / `rust_lineage_bump`
// FFI below. Keeping a single table eliminates the C/Rust desync that allowed a
// stale derived capability to pass one check while the other had been bumped.
//
// Each slot is an independent atomic so accesses are sound under future
// preemption / SMP. On the current single-core cooperative kernel the atomics
// compile down to plain loads/stores plus a `lock`-prefixed add.
const LINEAGE_SLOTS: usize = 4096;
#[allow(clippy::declare_interior_mutable_const)]
const LINEAGE_ZERO: AtomicU32 = AtomicU32::new(0);
static LINEAGE_GEN: [AtomicU32; LINEAGE_SLOTS] = [LINEAGE_ZERO; LINEAGE_SLOTS];



#[inline]
fn lineage_idx(obj: u64) -> usize {
    let mut x = obj;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x as usize) & (LINEAGE_SLOTS - 1)
}

/// Bump the generation for `obj`, invalidating every capability minted against
/// the previous generation. Returns the new generation. Generation 0 is reserved
/// to mean "untracked", so we skip it on wrap-around.
#[inline]
fn bump_lineage(obj: u64) -> u32 {
    if obj == 0 { return 0; }
    let idx = lineage_idx(obj);
    let prev = LINEAGE_GEN[idx].fetch_add(1, Ordering::SeqCst);
    let g = prev.wrapping_add(1);
    if g == 0 {
        // Wrapped back onto the reserved "untracked" value; force to 1.
        LINEAGE_GEN[idx].store(1, Ordering::SeqCst);
        1
    } else {
        g
    }
}

/// Authoritative validity check: is a capability that recorded `gen` for `obj`
/// still live? A cap is stale only when the lineage is tracked (`cg != 0`), the
/// cap carries a concrete generation (`gen != 0`), and they disagree.
#[inline]
fn lineage_check(obj: u64, gen: u32) -> bool {
    if obj == 0 { return true; }
    let cg = LINEAGE_GEN[lineage_idx(obj)].load(Ordering::SeqCst);
    !(cg != 0 && gen != 0 && gen != cg)
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_lookup(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    required_rights: u32,
) -> *mut Capability {
    if cspace.is_null() {
        return ptr::null_mut();
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return ptr::null_mut();
    }

    let cap = &mut *cspace.add(slot as usize);

    
    
    if cap.typ == CAP_NULL {
        return ptr::null_mut();
    }
    if (cap.rights & required_rights) != required_rights {
        return ptr::null_mut();
    }

    
    
    if cap.serial == 0 {
        return ptr::null_mut();
    }
    if cap.object != 0 && !lineage_check(cap.object, cap.generation) {
        return ptr::null_mut();
    }
    cap
}

/// Allocate a fresh derived serial, advancing `*next_serial`. This is the SINGLE
/// implementation of the serial wrap logic: serials never collide with the
/// reserved primordial range and never wrap to 0. Both `rust_cap_mint` and the C
/// `cap_alloc_fresh_serial` go through it so the two cannot drift.
#[inline]
unsafe fn assign_fresh_serial(next_serial: *mut u32) -> u32 {
    if next_serial.is_null() {

        return 0xC0DEFFFFu32;
    }
    let cur = *next_serial;


    let base = if cur < MIN_DERIVED_SERIAL { MIN_DERIVED_SERIAL } else { cur };
    let fresh = base.wrapping_add(1);
    let fresh = if fresh < MIN_DERIVED_SERIAL || fresh == 0 { MIN_DERIVED_SERIAL } else { fresh };
    *next_serial = fresh;
    fresh
}

/// FFI: centralized fresh-serial allocation for the C kernel. The caller holds
/// `cap_lock`; `next_serial` points at the kernel's monotonic serial counter.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_alloc_serial(next_serial: *mut u32) -> u32 {
    assign_fresh_serial(next_serial)
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_mint(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    new_rights: u32,
    next_serial: *mut u32,
    _current_task_caps_in_use: u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if dest_slot >= cspace_size || dest_slot >= CNODE_SIZE {
        return false;
    }
    if src_slot >= cspace_size || src_slot >= CNODE_SIZE {
        return false;
    }
    
    if dest_slot < KERNEL_RESERVED_CAPS {
        return false;
    }

    let src = &*cspace.add(src_slot as usize);
    if src.typ == CAP_NULL {
        return false;
    }
    
    if src.serial == 0 {
        return false;
    }

    let dest = &mut *cspace.add(dest_slot as usize);

    
    
    let parent_serial = src.serial;

    let fresh = assign_fresh_serial(next_serial);

    
    let effective_rights = new_rights & src.rights;

    *dest = Capability {
        typ: src.typ,
        rights: effective_rights,
        object: src.object,
        badge: parent_serial,
        serial: fresh,
        generation: src.generation,
    };
    if src.object != 0 {
        // Adopt the parent's generation as the floor for this lineage so the
        // authority never lags behind a legitimately-minted capability.
        LINEAGE_GEN[lineage_idx(src.object)].fetch_max(src.generation, Ordering::SeqCst);
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_transfer(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    next_serial: *mut u32,
) -> bool {
    rust_cap_mint(cspace, cspace_size, dest_slot, src_slot, !0u32, next_serial, 0)
}

/// Clear a capability slot to the null capability.
#[inline]
unsafe fn nullify(c: &mut Capability) {
    c.typ = CAP_NULL;
    c.rights = 0;
    c.object = 0;
    c.badge = 0;
    c.serial = 0;
    c.generation = 0;
}

// ---------------------------------------------------------------------------
// Transitive (precise) revocation.
//
// A derived capability records its *immediate* parent's serial in its `badge`
// (see `rust_cap_mint`: `badge: parent_serial`). The derivation relation is
// therefore a forest of parent-serial links, and revoking a capability means
// nulling exactly the subtree rooted at it — its children, grandchildren, and
// deeper — and nothing else.
//
// The old sweep matched by (serial | badge | object): matching `object` also
// caught unrelated capabilities that merely shared the same kernel object, and
// matching the target's own `badge` also caught its parent (an ancestor) and
// its siblings. That was both over-broad (K1) and the only thing that reached
// grandchildren (whose badge is the *child's* serial, not the target's). The
// walk below is precise AND transitive: it follows the real parent-serial links
// to a fixpoint, so ancestors, siblings, and independent same-object caps are
// left intact while every genuine descendant is revoked.
// ---------------------------------------------------------------------------

/// Scratch worklist for the transitive revocation walk, holding the serials of
/// capabilities whose children still need to be swept. Every revocation entry
/// point is called by C under `cap_lock`, so a single static buffer is sound on
/// the cooperative single-core kernel. Sized to the largest number of live caps
/// the system can hold — `MAX_TASKS` cspaces of `CNODE_SIZE` plus the kernel
/// root cnode — which bounds the length of any derivation chain, so the worklist
/// can never overflow.
const REVOKE_SCRATCH_CAP: usize = MAX_TASKS * CNODE_SIZE as usize + CNODE_SIZE as usize;
static mut REVOKE_WORKLIST: [u32; REVOKE_SCRATCH_CAP] = [0; REVOKE_SCRATCH_CAP];

/// Transitively revoke the derivation subtree rooted at `seed_serial`, sweeping
/// every cspace in `spaces`. The seed capability itself must already be nulled
/// by the caller; this walks the `badge == parent.serial` links to null every
/// descendant while leaving ancestors, siblings, and independent capabilities
/// that merely share the same object untouched. Decrements each space's
/// `caps_in_use` once per nulled cap when that pointer is non-null.
///
/// INVARIANT: this is the single mechanism by which the subtree is swept;
/// `rust_cap_revoke`, `rust_cap_revoke_global`, and `rust_cap_revoke_by_values`
/// all go through it so their matching semantics can never drift apart.
unsafe fn revoke_subtree(spaces: *const CSpaceDesc, space_count: u32, seed_serial: u32) {
    if seed_serial == 0 || spaces.is_null() {
        return;
    }
    // A serial of 0 means "no parent" (a primordial/root cap), so a stored 0 in
    // a badge never links to anything and is skipped below.
    let worklist = &mut *ptr::addr_of_mut!(REVOKE_WORKLIST);
    let mut head = 0usize;
    let mut tail = 0usize;
    worklist[tail] = seed_serial;
    tail += 1;

    while head < tail {
        let parent_serial = worklist[head];
        head += 1;
        for s in 0..space_count {
            let d = &*spaces.add(s as usize);
            if d.caps.is_null() {
                continue;
            }
            let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
            for i in 0..limit {
                let c = &mut *d.caps.add(i as usize);
                if c.typ == CAP_NULL {
                    continue;
                }
                // Match only the direct parent-serial link. Serials are unique,
                // so this identifies children of `parent_serial` and nothing
                // else — no ancestor, sibling, or same-object false positives.
                if c.badge != 0 && c.badge == parent_serial {
                    let child_serial = c.serial;
                    nullify(c);
                    if !d.caps_in_use.is_null() && *d.caps_in_use > 0 {
                        *d.caps_in_use -= 1;
                    }
                    // Enqueue the child so its own descendants are swept too.
                    // Bounded: each live cap is nulled (and thus enqueued) at
                    // most once, and the worklist is sized to the total cap
                    // count, so the guard can never actually drop a real entry.
                    if child_serial != 0 && tail < REVOKE_SCRATCH_CAP {
                        worklist[tail] = child_serial;
                        tail += 1;
                    }
                }
            }
        }
    }
}

#[inline]
unsafe fn is_primordial_root(cspace: *mut Capability, slot: u32) -> bool {
    let s = (*cspace.add(slot as usize)).serial;
    slot < KERNEL_RESERVED_CAPS && s != 0 && (s & 0xFFFF0000) == 0xC0DE0000
}

/// Single-cspace revoke. Used for moves and for revoking a CAP_REVOCATION
/// helper slot. For system-wide revocation use `rust_cap_revoke_global`.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    _next_serial: *mut u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return false;
    }
    if is_primordial_root(cspace, slot) {
        return false;
    }

    let target = &mut *cspace.add(slot as usize);
    if target.typ == CAP_NULL {
        return true;
    }

    let ts = target.serial;
    let to = target.object;

    nullify(target);

    // Single source of truth: bump the object's lineage generation once. This is
    // defense-in-depth against a snapshot escaping the structural sweep (TOCTOU);
    // its object-granularity is tracked separately (K2) and does not touch the
    // untracked gen-0 caps the structural walk below handles precisely.
    if to != 0 {
        let _ = bump_lineage(to);
    }

    // Precisely null the derivation subtree: the target's children, their
    // children, and so on — following the badge parent-serial links.
    let spaces = [CSpaceDesc { caps: cspace, size: cspace_size, caps_in_use: ptr::null_mut() }];
    revoke_subtree(spaces.as_ptr(), 1, ts);
    true
}

/// Descriptor for one capability space, passed across the FFI so the entire
/// system-wide revocation sweep happens inside one Rust call.
#[repr(C)]
pub struct CSpaceDesc {
    pub caps: *mut Capability,
    pub size: u32,
    /// Optional pointer to the owning task's `caps_in_use` counter; null to skip
    /// accounting (e.g. the kernel root cnode).
    pub caps_in_use: *mut u32,
}

/// SYSTEM-WIDE capability revocation — the authoritative revocation entry point.
///
/// Revokes the capability at `target_slot` of `target_cspace` and then sweeps
/// EVERY cspace in `spaces` (which the caller populates with all live tasks'
/// cspaces plus the kernel root cnode) for derived copies of the same lineage,
/// nulling them. The lineage generation is bumped exactly once, so any stale
/// copy that somehow escapes the structural sweep still fails the generation
/// check in `rust_cap_lookup`.
///
/// INVARIANT (see ARCHITECTURE.md): after this returns true, no live cspace
/// retains a capability whose serial/badge/object matches the revoked lineage.
/// This is what makes revocation complete rather than caller-local — closing
/// the use-after-revoke / privilege-retention hole where a derived capability
/// in another task's CNode could survive its parent's revocation.
///
/// Must be called by C under `cap_lock` so the `spaces` snapshot is stable.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_global(
    target_cspace: *mut Capability,
    target_cspace_size: u32,
    target_slot: u32,
    target_caps_in_use: *mut u32,
    spaces: *const CSpaceDesc,
    space_count: u32,
    _next_serial: *mut u32,
) -> bool {
    if target_cspace.is_null() {
        return false;
    }
    if target_slot >= target_cspace_size || target_slot >= CNODE_SIZE {
        return false;
    }
    if is_primordial_root(target_cspace, target_slot) {
        return false;
    }

    let target = &mut *target_cspace.add(target_slot as usize);
    if target.typ == CAP_NULL {
        return true;
    }

    let ts = target.serial;
    let to = target.object;

    // Null the target itself and account for it. The system-wide sweep below
    // walks from the target's serial and only matches descendants, so the
    // already-null target can never re-match and is never double-counted.
    nullify(target);
    if !target_caps_in_use.is_null() && *target_caps_in_use > 0 {
        *target_caps_in_use -= 1;
    }

    // Single source of truth: bump the object's lineage generation once (see the
    // note in `rust_cap_revoke`).
    if to != 0 {
        let _ = bump_lineage(to);
    }

    // Transitively null the derivation subtree across every supplied cspace. The
    // target's own cspace is among them; its slot is already null, so it cannot
    // re-match.
    revoke_subtree(spaces, space_count, ts);
    true
}

/// Single-cspace revoke by explicit values, behind the IPC snapshot/revalidate
/// (TOCTOU) guard. Nulls the capability identified by `target_serial` and its
/// derivation subtree within this one cspace, and bumps the object's lineage so
/// a snapshot taken before the revoke fails a generation re-check at point of
/// use. `target_badge` is retained for ABI stability (the C header declares it)
/// but is no longer used for matching — lineage is now followed precisely by the
/// parent-serial links, not by a badge/object broad match.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_by_values(
    cspace: *mut Capability,
    cspace_size: u32,
    target_serial: u32,
    target_badge: u32,
    target_obj: u64,
) -> bool {
    let _ = target_badge;
    if cspace.is_null() {
        return false;
    }
    // Bump lineage once for the object so generation checks also invalidate.
    if target_obj != 0 {
        let _ = bump_lineage(target_obj);
    }
    // Null the exact capability named by serial, then transitively revoke its
    // derivation subtree in this cspace.
    if target_serial != 0 {
        let limit = if cspace_size > CNODE_SIZE { CNODE_SIZE } else { cspace_size };
        for i in 0..limit {
            let c = &mut *cspace.add(i as usize);
            if c.typ != CAP_NULL && c.serial == target_serial {
                nullify(c);
            }
        }
        let spaces = [CSpaceDesc { caps: cspace, size: cspace_size, caps_in_use: ptr::null_mut() }];
        revoke_subtree(spaces.as_ptr(), 1, target_serial);
    }
    true
}

/// FFI: bump the lineage generation for `obj`. Sole way for C to invalidate a lineage.
#[no_mangle]
pub extern "C" fn rust_lineage_bump(obj: u64) -> u32 { bump_lineage(obj) }

/// FFI: check whether a capability recording `gen` for `obj` is still valid.
/// C's `capability_validate_generation` delegates here so both sides agree.
#[no_mangle]
pub extern "C" fn rust_lineage_check(obj: u64, gen: u32) -> bool { lineage_check(obj, gen) }

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;

    fn cap(typ: u32, rights: u32, object: u64, badge: u32, serial: u32, generation: u32) -> Capability {
        Capability { typ, rights, object, badge, serial, generation }
    }

    /// Regression: a derived capability minted into a *second* task's cspace
    /// must be revoked (and its lineage invalidated) when the parent is revoked
    /// in the first task — the system-wide revocation invariant.
    #[test]
    fn test_global_revoke_reaches_other_task_cspace() {
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];

        // Task A holds the parent CAP_FRAME (object 0x5000, serial 0x4000, gen 1).
        a[4] = cap(1, 0x3f, 0x5000, 0, 0x4000, 1);
        // Task B holds a derived copy: badge == parent serial, same object,
        // reduced rights, its own fresh serial — exactly what cap_mint produces.
        b[7] = cap(1, 0x03, 0x5000, 0x4000, 0x9001, 1);

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;

        unsafe {
            // Mirror reality: minting raises the lineage floor to the parent's
            // generation, so the table holds gen==1 for this object before the
            // revoke (which then bumps it to 2).
            while lineage_check(0x5000, 2) {
                let _ = bump_lineage(0x5000);
            }
            // Now cg == 1, matching the caps' recorded generation.

            // Precondition: B's derived cap is currently usable.
            assert!(!rust_cap_lookup(b.as_mut_ptr(), 16, 7, 0x1).is_null());

            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];

            let ok = rust_cap_revoke_global(
                a.as_mut_ptr(),
                16,
                4,
                addr_of_mut!(ciu_a),
                spaces.as_ptr(),
                2,
                core::ptr::null_mut(),
            );
            assert!(ok);

            // Parent revoked in task A.
            assert_eq!(a[4].typ, CAP_NULL);
            assert!(rust_cap_lookup(a.as_mut_ptr(), 16, 4, 0x1).is_null());

            // Derived copy in the OTHER task's cspace is gone — the core fix.
            assert_eq!(b[7].typ, CAP_NULL,
                "derived capability in another task must be revoked system-wide");
            assert!(rust_cap_lookup(b.as_mut_ptr(), 16, 7, 0x1).is_null());

            // Lineage generation bumped: a stale copy carrying the old gen fails
            // the generation check even if it had escaped the structural sweep.
            assert!(!lineage_check(0x5000, 1));

            // Accounting: both tasks' caps_in_use were decremented exactly once.
            assert_eq!(ciu_a, 0);
            assert_eq!(ciu_b, 0);
        }
    }

    /// A capability for a *different* object/lineage in another cspace must
    /// survive an unrelated revocation (no over-broad nulling).
    #[test]
    fn test_global_revoke_does_not_touch_unrelated() {
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];
        a[4] = cap(1, 0x3f, 0x7000, 0, 0x7700, 1);
        b[7] = cap(1, 0x3f, 0x8000, 0, 0x8800, 1); // unrelated lineage

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;
        unsafe {
            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            let ok = rust_cap_revoke_global(
                a.as_mut_ptr(), 16, 4, addr_of_mut!(ciu_a), spaces.as_ptr(), 2, core::ptr::null_mut());
            assert!(ok);
            assert!(!rust_cap_lookup(b.as_mut_ptr(), 16, 7, 0x1).is_null(),
                "unrelated capability must not be revoked");
            assert_eq!(ciu_b, 1);
        }
    }

    /// TRANSITIVE revocation across >1 generation: root -> child -> grandchild.
    /// Revoking the root must null the grandchild too. The grandchild's badge is
    /// its *immediate* parent's serial (not the root's), so this only works if
    /// revocation reaches beyond direct children.
    #[test]
    fn test_transitive_revoke_reaches_grandchild() {
        let obj = 0xB1B2_0001u64; // unique object -> own lineage slot
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        cs[4] = cap(1, 0x3f, obj, 0, 0x5000, 0); // root
        let mut next = 0x9000u32;
        unsafe {
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 5, 4, 0x3f, &mut next, 0)); // child
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 6, 5, 0x3f, &mut next, 0)); // grandchild
            // The grandchild links to its immediate parent (child), not the root.
            assert_eq!(cs[6].badge, cs[5].serial);
            assert_ne!(cs[6].badge, cs[4].serial);

            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut()));
            assert_eq!(cs[4].typ, CAP_NULL, "root revoked");
            assert_eq!(cs[5].typ, CAP_NULL, "child revoked");
            assert_eq!(cs[6].typ, CAP_NULL,
                "grandchild must be revoked transitively (>1 generation)");
        }
    }

    /// PRECISION (K1): two INDEPENDENT derivation trees over the *same* kernel
    /// object must not interfere. Revoking one root leaves the other tree wholly
    /// intact. The old object-match sweep nulled every cap sharing the object;
    /// the transitive walk follows lineage links, so the second tree survives.
    /// Uses untracked (gen-0) caps — the realistic frame-cap case — so the
    /// object-granular lineage bump does not mask the structural precision.
    #[test]
    fn test_independent_same_object_survives() {
        let obj = 0xC1C2_0001u64; // one shared object, two unrelated trees
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        cs[4] = cap(1, 0x3f, obj, 0, 0x6000, 0); // tree A root
        cs[8] = cap(1, 0x3f, obj, 0, 0x7000, 0); // tree B root (independent)
        let mut next = 0xA000u32;
        unsafe {
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 5, 4, 0x3f, &mut next, 0)); // A child
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 9, 8, 0x3f, &mut next, 0)); // B child

            // Revoke tree A's root only.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut()));
            assert_eq!(cs[4].typ, CAP_NULL, "A root revoked");
            assert_eq!(cs[5].typ, CAP_NULL, "A child revoked");

            // Tree B — same object, unrelated lineage — is untouched.
            assert_ne!(cs[8].typ, CAP_NULL,
                "independent same-object root must survive");
            assert_ne!(cs[9].typ, CAP_NULL,
                "independent same-object child must survive");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 8, 0x1).is_null());
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 9, 0x1).is_null());
        }
    }

    /// PRECISION (K1): revoking one child must NOT take out its siblings or its
    /// parent. Under the old sweep the target's badge (== parent serial) matched
    /// both the parent (serial == badge) and every sibling (badge == badge); the
    /// transitive walk seeds from the *child's* serial, so neither is touched.
    #[test]
    fn test_sibling_and_parent_survive() {
        let obj = 0xD1D2_0001u64;
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        cs[4] = cap(1, 0x3f, obj, 0, 0x8000, 0); // parent
        let mut next = 0xB000u32;
        unsafe {
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 5, 4, 0x3f, &mut next, 0)); // child 1
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 6, 4, 0x3f, &mut next, 0)); // child 2 (sibling)
            // Siblings share the parent's serial as their badge.
            assert_eq!(cs[5].badge, cs[4].serial);
            assert_eq!(cs[6].badge, cs[4].serial);

            // Revoke only child 1.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 5, core::ptr::null_mut()));
            assert_eq!(cs[5].typ, CAP_NULL, "child 1 revoked");

            // The sibling and the parent must both survive.
            assert_ne!(cs[6].typ, CAP_NULL, "sibling must survive");
            assert_ne!(cs[4].typ, CAP_NULL, "parent (ancestor) must survive");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 6, 0x1).is_null());
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 4, 0x1).is_null());
        }
    }

    #[test]
    fn test_lookup_and_mint_basic() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 42, badge: 0, serial: 0x1000, generation: 0 };

        let mut next = 0x1001u32;

        unsafe {
            let ok = rust_cap_mint(
                cspace.as_mut_ptr(),
                16,
                5,
                0,
                0x3,
                &mut next as *mut u32,
                0,
            );
            assert!(ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 5, 0x1);
            assert!(!looked.is_null());
            let c5 = &*looked;
            assert_eq!(c5.typ, 1);
            assert_eq!(c5.rights, 0x3);
            assert_eq!(c5.badge, 0x1000);
            assert!(c5.serial > 0x1000);
            assert_eq!(c5.generation, 0);
        }
    }

    #[test]
    fn test_revoke_clears_and_serial_is_fresh() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 99, badge: 0, serial: 0x2000, generation: 1 };

        let mut next = 0x2001u32;
        unsafe {
            let mint_ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 6, 0, 0x7, &mut next, 0);
            assert!(mint_ok);
            let child_before = *cspace.as_ptr().add(6);
            assert_eq!(child_before.badge, 0x2000);
            assert_eq!(child_before.generation, 1);

            
            let rev_ok = rust_cap_revoke(cspace.as_mut_ptr(), 16, 0, core::ptr::null_mut());
            assert!(rev_ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 6, 0x1);
            assert!(looked.is_null(), "derived cap must be revoked together with parent (badge lineage)");
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 0, 0).is_null());
        }
    }

    #[test]
    fn test_lineage_no_collision_on_low_bits() {
        
        
        
        let mut cs = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        unsafe {
            let ga = bump_lineage(0x1001);
            let gb = bump_lineage(0x1101);
            cs[4] = Capability { typ: 1, rights: 0x3f, object: 0x1001, badge: 0, serial: 0x100, generation: ga };
            cs[5] = Capability { typ: 1, rights: 0x3f, object: 0x1101, badge: 0, serial: 0x200, generation: gb };

            
            let _ = bump_lineage(0x1001);

            
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 4, 0x1).is_null(),
                "object 0x1001 should be stale after its lineage bump");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null(),
                "object 0x1101 must NOT be revoked by a bump targeting 0x1001");
        }
    }

    #[test]
    fn test_strict_rights_and_no_escalation() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 5, rights: 0b0011, object: 7, badge: 0, serial: 0x3000, generation: 0 };

        let mut next = 0x3001u32;
        unsafe {
            
            let ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 4, 0, 0xFFFF, &mut next, 0);
            assert!(ok);
            let child = &*rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0);
            
            assert_eq!(child.rights, 0b0011);
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0b0100).is_null());
        }
    }

    /// Serial allocation (the C kernel routes cap_alloc_fresh_serial through this
    /// FFI) must advance monotonically and never hand back a serial in the
    /// reserved primordial range or 0 — including at the u32 wrap boundary. Uses
    /// only a local counter, so it is fully deterministic under parallel tests.
    #[test]
    fn test_alloc_serial_stays_above_reserved_and_nonzero() {
        unsafe {
            // Starting below the floor snaps up to the first derived serial.
            let mut s: u32 = 0;
            let a = rust_cap_alloc_serial(&mut s);
            assert!(a >= MIN_DERIVED_SERIAL);
            assert_eq!(s, a, "counter is advanced in place");
            let b = rust_cap_alloc_serial(&mut s);
            assert!(b > a && b >= MIN_DERIVED_SERIAL);

            // At the wrap boundary it must not yield 0 or dip below the floor.
            let mut w: u32 = u32::MAX;
            let f = rust_cap_alloc_serial(&mut w);
            assert!(f >= MIN_DERIVED_SERIAL && f != 0);

            // A null counter returns the sentinel rather than dereferencing null.
            assert_eq!(rust_cap_alloc_serial(core::ptr::null_mut()), 0xC0DEFFFF);
        }
    }

    /// A primordial root capability (serial prefix `0xC0DE`, sitting in a
    /// kernel-reserved slot) must survive BOTH single-cspace and system-wide
    /// revocation — the check refuses before any mutation, so the cap stays
    /// intact and usable. This is what stops a userspace path from revoking a
    /// system-critical root capability.
    #[test]
    fn test_primordial_root_cannot_be_revoked() {
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        // slot 2 is within KERNEL_RESERVED_CAPS (4); the serial carries the
        // primordial 0xC0DE prefix. generation 0 == untracked, so lookups do
        // not depend on the shared lineage table (parallel-test safe).
        cs[2] = cap(9 /*CAP_ENCRYPTED_STORAGE*/, 0x3f, 0xA011, 0, 0xC0DE0002, 0);
        unsafe {
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 2, 0x1).is_null(),
                "primordial cap is usable to begin with");

            // Single-cspace revoke refuses and leaves the slot untouched.
            assert!(!rust_cap_revoke(cs.as_mut_ptr(), 16, 2, core::ptr::null_mut()));
            assert_eq!(cs[2].serial, 0xC0DE0002, "primordial cap must be untouched");

            // System-wide revoke refuses too, and performs no sweep.
            let spaces = [CSpaceDesc { caps: cs.as_mut_ptr(), size: 16, caps_in_use: core::ptr::null_mut() }];
            assert!(!rust_cap_revoke_global(
                cs.as_mut_ptr(), 16, 2, core::ptr::null_mut(),
                spaces.as_ptr(), 1, core::ptr::null_mut()));
            assert_eq!(cs[2].typ, 9);
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 2, 0x1).is_null(),
                "primordial cap remains usable after an attempted revocation");
        }
    }

    /// `rust_cap_transfer` copies a capability with the source's full (unmasked)
    /// rights and the parent's serial as its badge, and the copy shares the
    /// parent's lineage: revoking the source clears the transferred copy too.
    #[test]
    fn test_transfer_copies_rights_and_shares_lineage() {
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        cs[4] = cap(4 /*CAP_FRAME*/, 0x3f, 0xA200, 0, 0xA201, 0);
        let mut next = 0x20000u32;
        unsafe {
            assert!(rust_cap_transfer(cs.as_mut_ptr(), 16, 8, 4, &mut next));
            let d = cs[8];
            assert_eq!(d.typ, 4);
            assert_eq!(d.rights, 0x3f, "transfer preserves the source's full rights");
            assert_eq!(d.object, 0xA200);
            assert_eq!(d.badge, 0xA201, "the copy records the source serial as its badge");
            assert!(d.serial >= MIN_DERIVED_SERIAL && d.serial != 0xA201,
                "the copy gets a fresh serial, distinct from the source");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 8, 0x3f).is_null());

            // Revoking the source lineage clears the transferred copy as well.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut()));
            assert_eq!(cs[4].typ, CAP_NULL);
            assert_eq!(cs[8].typ, CAP_NULL,
                "a transferred copy is revoked together with its source (shared lineage)");
        }
    }

    /// The lineage generation counter reserves 0 to mean "untracked". A bump that
    /// wraps `u32::MAX` back to 0 must skip the reserved value and land on 1, and
    /// a capability that recorded the pre-wrap generation must read as stale — so
    /// use-after-revoke is prevented even across the counter wrap.
    #[test]
    fn test_lineage_generation_wraparound() {
        let obj = 0xA5A5_0001u64; // unique object -> its own lineage slot
        let idx = lineage_idx(obj);
        // Drive the slot to the wrap boundary directly (a 4-billion-bump loop
        // would be absurd); the store mirrors a counter about to overflow.
        LINEAGE_GEN[idx].store(u32::MAX, core::sync::atomic::Ordering::SeqCst);

        // A capability minted at the pre-wrap generation is valid right now.
        assert!(lineage_check(obj, u32::MAX));

        // Bump: u32::MAX --(wrap)--> 0 --(skip reserved)--> 1.
        let g = bump_lineage(obj);
        assert_ne!(g, 0, "a wrapped generation must never be the reserved 0");
        assert_eq!(g, 1, "the wrap must land on 1");

        // The pre-wrap capability is now stale.
        assert!(!lineage_check(obj, u32::MAX),
            "a capability recording the pre-wrap generation must be invalid");
        // A freshly minted cap (generation 1) is valid; generation 0 always
        // passes by design (the untracked sentinel).
        assert!(lineage_check(obj, 1));
        assert!(lineage_check(obj, 0));
    }

    /// `rust_cap_revoke_by_values` is the explicit-values, single-cspace revoke
    /// behind the IPC snapshot/revalidate guard: it nulls every matching
    /// capability AND bumps the object's lineage, so a snapshot a caller took
    /// before the revoke fails a generation re-check at point of use (the TOCTOU
    /// close).
    #[test]
    fn test_revoke_by_values_invalidates_snapshot() {
        let obj = 0xA300u64;
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        unsafe {
            let g = bump_lineage(obj); // establish a concrete tracked generation
            cs[5] = cap(3 /*CAP_ENDPOINT*/, 0x3f, obj, 0, 0xA301, g);
            // What a caller snapshotted for a later revalidate-at-use.
            let snapshot = cs[5];
            assert!(lineage_check(snapshot.object, snapshot.generation),
                "snapshot is valid before the revoke");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null());

            assert!(rust_cap_revoke_by_values(cs.as_mut_ptr(), 16, 0xA301, 0, obj));

            // The live slot is nulled structurally...
            assert_eq!(cs[5].typ, CAP_NULL);
            // ...and the pre-revoke snapshot fails the generation re-check.
            assert!(!lineage_check(snapshot.object, snapshot.generation),
                "a pre-revoke snapshot must fail the generation re-check (TOCTOU guard)");
        }
    }
}
