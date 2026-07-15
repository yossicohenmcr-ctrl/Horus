//! Device-capability range validators (ring-3 driver framework).
//!
//! When a hardware driver is moved out of ring 0 into a userspace server, the
//! kernel must decide, from an unforgeable `CAP_IO_PORT` / `CAP_MMIO` capability,
//! exactly which x86 I/O ports or which physical MMIO region that driver may
//! touch — and it must get the arithmetic right, because an off-by-one or an
//! overflow here silently widens a driver's hardware reach past what its
//! capability grants. That bounds math lives here, in safe Rust: fail-closed,
//! overflow-safe, pure value predicates (no pointer deref), unit-tested and
//! fuzzed, consistent with the crate's other FFI validators
//! (`rust_signal_handler_addr_ok`, `rust_page_is_valid_user_phys`).
//!
//! Encoding (kernel-side, `capability.h`):
//!   * `CAP_IO_PORT.object = (base << 16) | count`  — port window `[base, base+count)`
//!   * `CAP_MMIO.object    = phys base`, length carried separately (`badge`)
//!
//! x86 has 65536 I/O ports (`0x0000..=0xFFFF`), so a well-formed window satisfies
//! `count >= 1` and `base + count <= 65536`.

const IO_PORT_SPACE: u64 = 0x1_0000; // 65536 ports

/// Decode a `CAP_IO_PORT.object` into `(base, count)` without validating it.
#[inline]
fn io_window(cap_object: u64) -> (u64, u64) {
    let base = (cap_object >> 16) & 0xFFFF;
    let count = cap_object & 0xFFFF;
    (base, count)
}

/// True iff `cap_object` encodes a well-formed, non-empty I/O-port window that
/// fits inside the 64K port space. The kernel calls this before caching a
/// `CAP_IO_PORT` window into a task's TSS I/O bitmap, so a malformed capability
/// opens *no* ports rather than wrapping around the port space.
#[no_mangle]
pub extern "C" fn rust_io_port_window_ok(cap_object: u64) -> bool {
    let (base, count) = io_window(cap_object);
    count >= 1 && base + count <= IO_PORT_SPACE
}

/// True iff the requested port window `[req_base, req_base + req_count)` is
/// non-empty and fully contained in the window granted by `cap_object`. All
/// arithmetic is done in `u64` so no `u16`/`u32` overflow can make an
/// out-of-range request look in-range. Fail-closed: a malformed capability or a
/// zero-length / out-of-bounds request returns `false`.
#[no_mangle]
pub extern "C" fn rust_io_port_range_ok(cap_object: u64, req_base: u32, req_count: u32) -> bool {
    if !rust_io_port_window_ok(cap_object) {
        return false;
    }
    let (cbase, ccount) = io_window(cap_object);
    let (rbase, rcount) = (req_base as u64, req_count as u64);
    if rcount == 0 || rbase >= IO_PORT_SPACE {
        return false;
    }
    let rend = rbase + rcount; // <= 0xFFFF + 0xFFFF_FFFF, no overflow in u64
    let cend = cbase + ccount;
    rbase >= cbase && rend <= cend
}

/// True iff the requested physical MMIO span `[req_phys, req_phys + req_len)` is
/// non-empty and fully contained in the region a `CAP_MMIO` grants
/// (`[cap_object, cap_object + cap_len)`). Overflow-safe in `u128`. Used by the
/// console phase to map e.g. the VGA text buffer into a driver's address space.
#[no_mangle]
pub extern "C" fn rust_mmio_region_ok(
    cap_object: u64,
    cap_len: u64,
    req_phys: u64,
    req_len: u64,
) -> bool {
    if cap_len == 0 || req_len == 0 {
        return false;
    }
    let cend = cap_object as u128 + cap_len as u128;
    let rend = req_phys as u128 + req_len as u128;
    (req_phys as u128) >= (cap_object as u128) && rend <= cend
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(base: u16, count: u16) -> u64 {
        ((base as u64) << 16) | (count as u64)
    }

    #[test]
    fn io_window_wellformed() {
        assert!(rust_io_port_window_ok(window(0x1F0, 8))); // ATA data window
        assert!(rust_io_port_window_ok(window(0x3F6, 1))); // ATA control
        // count 0 is malformed (a zero-length window grants nothing)
        assert!(!rust_io_port_window_ok(window(0x60, 0)));
        // base+count overflowing the port space is malformed
        assert!(!rust_io_port_window_ok(window(0xFFFF, 2)));
        assert!(rust_io_port_window_ok(window(0xFFFF, 1))); // last single port is fine
    }

    #[test]
    fn io_range_subset() {
        let cap = window(0x1F0, 8); // [0x1F0, 0x1F8)
        assert!(rust_io_port_range_ok(cap, 0x1F0, 8)); // exactly the window
        assert!(rust_io_port_range_ok(cap, 0x1F0, 1)); // first port
        assert!(rust_io_port_range_ok(cap, 0x1F7, 1)); // last port
        assert!(!rust_io_port_range_ok(cap, 0x1F0, 9)); // one past the end
        assert!(!rust_io_port_range_ok(cap, 0x1EF, 1)); // one before the start
        assert!(!rust_io_port_range_ok(cap, 0x1F8, 1)); // just past the window
        assert!(!rust_io_port_range_ok(cap, 0x1F0, 0)); // empty request
        // a request whose base+count overflows u32 must not wrap into range
        assert!(!rust_io_port_range_ok(cap, 0xFFFF_FFF0, 0x20));
        // a malformed capability grants nothing
        assert!(!rust_io_port_range_ok(window(0x60, 0), 0x60, 1));
    }

    #[test]
    fn mmio_subset() {
        let base = 0xB8000u64;
        let len = 0x1000u64; // one page of VGA text memory
        assert!(rust_mmio_region_ok(base, len, base, len));
        assert!(rust_mmio_region_ok(base, len, base, 0x80));
        assert!(!rust_mmio_region_ok(base, len, base, len + 1));
        assert!(!rust_mmio_region_ok(base, len, base - 1, 0x10));
        assert!(!rust_mmio_region_ok(base, len, base, 0)); // empty
        assert!(!rust_mmio_region_ok(base, 0, base, len)); // empty cap
        // near u64::MAX, the u128 arithmetic must not wrap into a false accept
        assert!(!rust_mmio_region_ok(u64::MAX - 4, 4, u64::MAX - 4, 8));
    }

    // ---- property fuzz (zero-dependency; see rust/src/fuzzrng.rs) ----

    #[test]
    fn fuzz_io_port_range_never_escapes_window() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0x0D_E71C_E000_0001);
        for _ in 0..200_000 {
            let cap = r.next_u64();
            let req_base = r.next_u32();
            let req_count = r.next_u32();
            // Never panics (no overflow), and any accepted request is a real
            // subset of a well-formed window that stays inside the port space.
            if rust_io_port_range_ok(cap, req_base, req_count) {
                assert!(rust_io_port_window_ok(cap));
                let (cbase, ccount) = io_window(cap);
                let rbase = req_base as u64;
                let rend = rbase + req_count as u64;
                assert!(rbase >= cbase && rend <= cbase + ccount);
                assert!(rend <= IO_PORT_SPACE);
                assert!(req_count > 0);
            }
        }
    }

    #[test]
    fn fuzz_mmio_region_never_escapes() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0x0D_E71C_E000_0002);
        for _ in 0..200_000 {
            let cbase = r.next_u64();
            let clen = r.next_u64();
            let rphys = r.next_u64();
            let rlen = r.next_u64();
            if rust_mmio_region_ok(cbase, clen, rphys, rlen) {
                assert!(clen > 0 && rlen > 0);
                let cend = cbase as u128 + clen as u128;
                let rend = rphys as u128 + rlen as u128;
                assert!(rphys as u128 >= cbase as u128 && rend <= cend);
            }
        }
    }
}
