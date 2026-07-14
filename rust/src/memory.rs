use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

pub const USER_PHYS_PAGES: u32 = 16384;
pub const USER_PHYS_BASE: u32 = 0x01000000;
pub const PAGE_SIZE: u32 = 4096;

// ---------------------------------------------------------------------------
// Refcount-table trust boundary.
//
// These functions write into a `*mut u16` array supplied by C. Bounds checks
// alone are not enough: a buggy C caller that passes a wrong pointer or a
// `n_pages` larger than the real array would let Rust write out of bounds (UB
// in the combined binary). To close that, C must register the one true table
// once via `rust_page_refcounts_register`; every subsequent inc/dec then
// requires the supplied (pointer, length) to match the registered table
// exactly, and the length to equal the compile-time `USER_PHYS_PAGES`. A
// mismatch is refused rather than trusted.
// ---------------------------------------------------------------------------
static REFC_PTR: AtomicUsize = AtomicUsize::new(0);
static REFC_LEN: AtomicU32 = AtomicU32::new(0);

/// Register the authoritative refcount table. Must be called once at paging
/// init before any inc/dec. Rejects anything but the expected fixed-size table.
#[no_mangle]
pub unsafe extern "C" fn rust_page_refcounts_register(refcounts: *const u16, n_pages: u32) -> bool {
    if refcounts.is_null() || n_pages != USER_PHYS_PAGES {
        return false;
    }
    REFC_PTR.store(refcounts as usize, Ordering::SeqCst);
    REFC_LEN.store(n_pages, Ordering::SeqCst);
    true
}

/// True iff (refcounts, n_pages) is the exact table that was registered.
#[inline]
fn refc_table_ok(refcounts: *const u16, n_pages: u32) -> bool {
    let p = REFC_PTR.load(Ordering::SeqCst);
    let l = REFC_LEN.load(Ordering::SeqCst);
    p != 0 && p == refcounts as usize && l == n_pages && n_pages == USER_PHYS_PAGES
}

#[no_mangle]
pub unsafe extern "C" fn rust_page_ref_inc(phys: u32, refcounts: *mut u16, n_pages: u32) -> u16 {
    if !refc_table_ok(refcounts as *const u16, n_pages) {
        return 0;
    }
    if phys < USER_PHYS_BASE {
        return 0;
    }
    let idx32 = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if idx32 >= n_pages {
        return 0;
    }
    let idx = idx32 as usize;
    let cur = *refcounts.add(idx);
    let next = cur.saturating_add(1);
    *refcounts.add(idx) = next;
    next
}

#[no_mangle]
pub unsafe extern "C" fn rust_page_ref_dec(phys: u32, refcounts: *mut u16, n_pages: u32) -> i32 {
    if !refc_table_ok(refcounts as *const u16, n_pages) {
        return -1;
    }
    if phys < USER_PHYS_BASE {
        return -1;
    }
    let idx32 = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if idx32 >= n_pages {
        return -1;
    }
    let idx = idx32 as usize;
    let cur = *refcounts.add(idx);
    if cur == 0 {
        return -2;
    }
    let next = cur - 1;
    *refcounts.add(idx) = next;
    next as i32
}

#[no_mangle]
pub unsafe extern "C" fn rust_page_is_valid_user_phys(phys: u32, n_pages: u32) -> bool {
    if n_pages != USER_PHYS_PAGES {
        return false;
    }
    if phys < USER_PHYS_BASE {
        return false;
    }
    let idx = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    idx < n_pages
}

#[no_mangle]
pub unsafe extern "C" fn rust_alloc_user_physical_page(
    free_stack: *mut u32,
    free_count: *mut i32,
    n_pages: u32,
) -> u32 {
    if free_stack.is_null() || free_count.is_null() || n_pages != USER_PHYS_PAGES {
        return 0;
    }
    let cnt = *free_count;
    if cnt <= 0 {
        return 0;
    }
    let new_cnt = cnt - 1;
    let phys = *free_stack.add(new_cnt as usize);
    if !rust_page_is_valid_user_phys(phys, n_pages) {
        return 0;
    }
    *free_count = new_cnt;
    phys
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_user_physical_page(
    phys: u32,
    free_stack: *mut u32,
    free_count: *mut i32,
    n_pages: u32,
) -> bool {
    if free_stack.is_null() || free_count.is_null() || n_pages != USER_PHYS_PAGES {
        return false;
    }
    if !rust_page_is_valid_user_phys(phys, n_pages) {
        return false;
    }
    let cnt = *free_count;
    if cnt < 0 || (cnt as u32) >= n_pages {
        return false;
    }
    *free_stack.add(cnt as usize) = phys;
    *free_count = cnt + 1;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- property fuzz (zero-dependency; see rust/src/fuzzrng.rs) ----

    // The user-physical-page bounds check must exactly match its specification
    // for every 32-bit address (below the base, in range, and past the top) and
    // must never panic on the boundary subtraction/division.
    #[test]
    fn fuzz_valid_user_phys_matches_spec() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0x000E_A000_0001);
        for _ in 0..200000 {
            // Bias toward in-range addresses so both branches are exercised.
            let phys = if r.below(2) == 0 {
                r.next_u32()
            } else {
                USER_PHYS_BASE.wrapping_add(r.below(USER_PHYS_PAGES * PAGE_SIZE))
            };
            let n_pages = if r.below(4) == 0 { r.next_u32() } else { USER_PHYS_PAGES };
            let expect = n_pages == USER_PHYS_PAGES
                && phys >= USER_PHYS_BASE
                && (phys - USER_PHYS_BASE) / PAGE_SIZE < n_pages;
            let got = unsafe { rust_page_is_valid_user_phys(phys, n_pages) };
            assert_eq!(got, expect, "phys={phys:#x} n_pages={n_pages}");
        }
    }

    // The (pointer, length) trust boundary: inc/dec against a table that was
    // never registered — or whose length disagrees — must be refused before any
    // indexing, returning 0 / -1 for arbitrary phys and never dereferencing.
    #[test]
    fn fuzz_refcount_rejects_unregistered_table() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0x000E_A000_0002);
        let mut table = [0u16; 32]; // deliberately NOT the registered table
        for _ in 0..100000 {
            let phys = r.next_u32();
            let n_pages = if r.below(2) == 0 { r.next_u32() } else { USER_PHYS_PAGES };
            unsafe {
                // A local, unregistered pointer can never equal the global
                // REFC_PTR, so refc_table_ok fails and no indexing occurs.
                assert_eq!(rust_page_ref_inc(phys, table.as_mut_ptr(), n_pages), 0);
                assert_eq!(rust_page_ref_dec(phys, table.as_mut_ptr(), n_pages), -1);
            }
        }
    }

    const N: u32 = USER_PHYS_PAGES;
    fn phys_of(page: u32) -> u32 {
        USER_PHYS_BASE + page * PAGE_SIZE
    }

    // The refcount table is guarded by process-global registered (ptr, len).
    // Keep every assertion that depends on that global in ONE test so parallel
    // tests can never clobber the registration between register and use. This
    // is the only test in the crate that calls rust_page_refcounts_register.
    #[test]
    fn refcount_trust_boundary() {
        let mut table = [0u16; USER_PHYS_PAGES as usize];
        let ptr = table.as_mut_ptr();
        let other = [0u16; 4];

        unsafe {
            // Registration accepts only the one true fixed-size table.
            assert!(!rust_page_refcounts_register(core::ptr::null(), N));
            assert!(!rust_page_refcounts_register(ptr, N - 1));
            assert!(!rust_page_refcounts_register(ptr, N + 1));
            assert!(rust_page_refcounts_register(ptr, N));

            // Zero-trust: inc/dec touch memory only when (ptr, len) is the exact
            // registered table — a wrong pointer or length is refused, never
            // dereferenced.
            assert_eq!(rust_page_ref_inc(phys_of(0), other.as_ptr() as *mut u16, N), 0);
            assert_eq!(rust_page_ref_inc(phys_of(0), ptr, N - 1), 0);
            assert_eq!(rust_page_ref_dec(phys_of(0), other.as_ptr() as *mut u16, N), -1);

            // Below the user base and one-past-the-end pages are refused.
            assert_eq!(rust_page_ref_inc(USER_PHYS_BASE - 1, ptr, N), 0);
            assert_eq!(rust_page_ref_inc(phys_of(N), ptr, N), 0);

            // Normal inc/dec round-trips on a valid page.
            assert_eq!(rust_page_ref_inc(phys_of(5), ptr, N), 1);
            assert_eq!(rust_page_ref_inc(phys_of(5), ptr, N), 2);
            assert_eq!(rust_page_ref_dec(phys_of(5), ptr, N), 1);
            assert_eq!(rust_page_ref_dec(phys_of(5), ptr, N), 0);
            // Decrementing a zero refcount is reported (-2), never underflowed.
            assert_eq!(rust_page_ref_dec(phys_of(5), ptr, N), -2);
            assert_eq!(table[5], 0);

            // inc saturates at u16::MAX rather than wrapping to a bogus 0.
            table[6] = u16::MAX;
            assert_eq!(rust_page_ref_inc(phys_of(6), ptr, N), u16::MAX);
            assert_eq!(table[6], u16::MAX, "saturated count persists in the table");
        }
    }

    #[test]
    fn valid_user_phys_bounds() {
        unsafe {
            assert!(!rust_page_is_valid_user_phys(USER_PHYS_BASE - 1, N));
            assert!(rust_page_is_valid_user_phys(USER_PHYS_BASE, N));
            assert!(rust_page_is_valid_user_phys(phys_of(N - 1), N));
            assert!(!rust_page_is_valid_user_phys(phys_of(N), N));
            // Only the exact compile-time page count is trusted.
            assert!(!rust_page_is_valid_user_phys(USER_PHYS_BASE, N - 1));
            assert!(!rust_page_is_valid_user_phys(USER_PHYS_BASE, 0));
        }
    }

    #[test]
    fn alloc_free_physical_page() {
        let mut stack = [0u32; 64];
        stack[0] = phys_of(10);
        stack[1] = phys_of(11);
        stack[2] = phys_of(12);
        let mut count: i32 = 3;

        unsafe {
            // Null pointers / wrong page count are refused and must not mutate
            // the counter.
            assert_eq!(rust_alloc_user_physical_page(core::ptr::null_mut(), &mut count, N), 0);
            assert_eq!(rust_alloc_user_physical_page(stack.as_mut_ptr(), &mut count, N - 1), 0);
            assert_eq!(count, 3);

            // LIFO pop.
            assert_eq!(rust_alloc_user_physical_page(stack.as_mut_ptr(), &mut count, N), phys_of(12));
            assert_eq!(count, 2);

            // Free rejects an out-of-range phys but accepts a valid one.
            assert!(!rust_free_user_physical_page(USER_PHYS_BASE - 1, stack.as_mut_ptr(), &mut count, N));
            assert!(rust_free_user_physical_page(phys_of(12), stack.as_mut_ptr(), &mut count, N));
            assert_eq!(count, 3);

            // Exhaustion returns 0 rather than reading past the stack.
            let mut empty: i32 = 0;
            assert_eq!(rust_alloc_user_physical_page(stack.as_mut_ptr(), &mut empty, N), 0);
        }
    }
}


