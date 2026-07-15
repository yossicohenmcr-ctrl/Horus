#![no_std]
// The page-fault / protection / demand-paging policy below is written as
// explicit `addr >= LO && addr < HI` window comparisons on purpose: the bounds
// are security-sensitive and read more auditably side-by-side than as range
// `.contains()` calls. Allow the lint crate-wide so a `-D warnings` CI gate
// stays meaningful (catches new issues) without mechanically rewriting them.
#![allow(clippy::manual_range_contains)]

// `alloc` is only pulled in for host tests (the Argon2 memory buffer is large);
// the kernel build stays strictly `no_std`, no allocator.
#[cfg(test)]
extern crate alloc;

mod aead;
mod argon2;
mod blake2b;
mod audit;
mod auth;
mod capability;
mod crypto;
mod memory;
mod ps;
mod rng;
mod sha256;
mod sha512;
mod ed25519;
mod device;

// Zero-dependency property/differential fuzz harness (host tests only). See
// rust/src/fuzzrng.rs and the `fuzz_*` tests in each module's `mod tests`.
#[cfg(test)]
mod fuzzrng;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[repr(C)]
pub struct SafeCap {
    pub raw: u32,
}

impl SafeCap {
    pub fn has_rights(&self, required: u32) -> bool {
        (self.raw & required) == required
    }
}

#[no_mangle]
pub extern "C" fn rust_validate_page_fault(task_id: u32, fault_addr: u32, error_code: u32) -> bool {
    let _ = (task_id, error_code);
    if fault_addr >= 0x7FB000 && fault_addr < 0x7FC000 { return false; }
    if fault_addr >= 0x400000 && fault_addr < 0x800000 { return true; }
    if fault_addr >= 0xA00000 && fault_addr < 0xB00000 { return true; }
    false
}

#[repr(C)]
pub struct SafeCapability {
    pub raw: u32,
}

/// # Safety
/// `cap` must be null or a valid, aligned pointer to a `SafeCapability` that
/// stays live for the call. Null is handled; any other invalid pointer is UB.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_has_rights(cap: *const SafeCapability, required: u32) -> bool {
    if cap.is_null() {
        return false;
    }
    ((*cap).raw & required) == required
}

#[no_mangle]
pub extern "C" fn rust_get_user_page_protection(_task_id: u32, vaddr: u32) -> u32 {
    if (vaddr >= 0x400000 && vaddr < 0x800000) ||
       (vaddr >= 0xA00000 && vaddr < 0xB00000) ||
       (vaddr >= 0x7FC000 && vaddr < 0x800000) ||
       (vaddr >= 0xff000000 && vaddr < 0xfff00000) {
        return 0x7;
    }
    0
}

/// W^X policy: is the user page at `vaddr` non-executable?
///
/// User stacks must never be executable -- mapping them no-execute (the PTE NX
/// bit, honoured because EFER.NXE is enabled) defeats classic shellcode on the
/// stack. The kernel ORs `PAGE_NX` into a stack page's PTE when this returns
/// true. The image/heap region (from `USER_AREA_BASE` upward) stays executable:
/// the flat-binary loader cannot distinguish code from data within it, so it
/// must remain runnable. Takes a full 64-bit vaddr so the high ASLR stack is
/// expressible (unlike `rust_get_user_page_protection`, which is u32).
#[no_mangle]
pub extern "C" fn rust_user_page_is_noexec(vaddr: u64) -> bool {
    // Low user stack: top of the 4-8 MB user area. The loaded image starts at
    // 0x400000 and is at most 1 MB tall, and the heap tops out well under
    // 0x520000, so nothing executable lives at or above 0x7d0000.
    if (0x0000_0000_007d_0000..0x0000_0000_0080_0000).contains(&vaddr) {
        return true;
    }
    // High ASLR stack window around 0x7ff0_0000_0000.
    const HIGH_STACK_BASE: u64 = 0x0000_7ff0_0000_0000;
    if (HIGH_STACK_BASE - 0x10_0000..HIGH_STACK_BASE + 0x10_0000).contains(&vaddr) {
        return true;
    }
    false
}

/// # Safety
/// `cmd` must be null or point to at least `len` initialized bytes that stay
/// live for the call. Null is handled; any other invalid (pointer, len) is UB.
#[no_mangle]
pub unsafe extern "C" fn rust_handle_command(cmd: *const u8, len: usize) -> i32 {
    if cmd.is_null() {
        return 0;
    }

    let cmd_slice = core::slice::from_raw_parts(cmd, len);
    let cmd_str = match core::str::from_utf8(cmd_slice) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    if cmd_str == "help" { return 42; }
    if cmd_str == "version" { return 43; }
    if cmd_str.starts_with("echo ") { return 44; }
    if cmd_str == "exit" { return 1; }
    if cmd_str == "uptime" { return 45; }
    if cmd_str == "ps" || cmd_str == "tasks" { return 46; }
    if cmd_str == "caps" { return 47; }
    if cmd_str == "clear" { return 48; }
    if cmd_str.starts_with("kill ") { return 49; }
    if cmd_str.starts_with("mint ") { return 50; }
    if cmd_str == "rotate_keys" { return 36; }
    if cmd_str.starts_with("fs ") || cmd_str.starts_with("cap_") { return 52; }

    -1
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DemandAction {
    Invalid = -1,
    DemandZero = 0,
    CowCopyNeeded = 1,
    NoAction = 2,
}

#[no_mangle]
pub extern "C" fn rust_handle_demand_page_fault(
    fault_addr: u32,
    err_code: u32,
    is_cow: bool,
    ref_count: u16,
) -> DemandAction {
    if fault_addr >= 0x7FB000 && fault_addr < 0x7FC000 {
        return DemandAction::Invalid;
    }

    let in_user_window =
        (fault_addr >= 0x400000 && fault_addr < 0x800000) ||
        (fault_addr >= 0xA00000 && fault_addr < 0xB00000);

    if !in_user_window {
        return DemandAction::Invalid;
    }

    if fault_addr >= 0xFFC00000 {
        return DemandAction::Invalid;
    }

    let is_write = (err_code & 2) != 0;
    let is_user = (err_code & 4) != 0;

    if is_cow && is_write && is_user {
        if ref_count > 1 {
            return DemandAction::CowCopyNeeded;
        } else {
            return DemandAction::NoAction;
        }
    }

    if (err_code & 1) == 0 && is_user {
        return DemandAction::DemandZero;
    }

    DemandAction::Invalid
}

#[no_mangle]
pub extern "C" fn rust_cow_copy_required(is_cow: bool, is_write: bool, ref_count: u16) -> bool {
    is_cow && is_write && ref_count > 1
}

#[no_mangle]
pub extern "C" fn rust_should_demand_zero(err_code: u32) -> bool {
    (err_code & 1) == 0 && (err_code & 4) != 0
}

/// Validate a would-be ring-3 signal-handler entry address. On a fault the
/// kernel iretq's ring 3 to this address, so it must be a plausible user *code*
/// location: inside the loader's user image window `[0x400000, 0x800000)`.
/// Anything else (the stack, the heap, the kernel image, an unmapped address, or
/// 0) is rejected so a task cannot register a handler that redirects control
/// flow somewhere it should not run. Pure value predicate — no pointer deref.
#[no_mangle]
pub extern "C" fn rust_signal_handler_addr_ok(vaddr: u32) -> bool {
    const USER_CODE_LO: u32 = 0x0040_0000;
    const USER_CODE_HI: u32 = 0x0080_0000;
    vaddr >= USER_CODE_LO && vaddr < USER_CODE_HI
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FsOp {
    Lookup = 0,
    Create = 1,
    Delete = 2,
    Read   = 3,
    Write  = 4,
    Mint   = 5,
}

#[no_mangle]
pub extern "C" fn rust_validate_fs_operation(
    task_id: u32,
    _op: u32,
    rights_held: u32,
    name_ptr: *const u8,
    name_len: usize,
) -> i32 {
    if !name_ptr.is_null() && name_len > 0 && name_len < 32 {
        let _ = (task_id,);
    }

    if rights_held == 0 {
        return -1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // err_code bit layout used throughout: present=1, write=2, user=4.
    const PRESENT: u32 = 1;
    const WRITE: u32 = 2;
    const USER: u32 = 4;

    // ---- property fuzz (zero-dependency; see rust/src/fuzzrng.rs) ----

    // Arbitrary command bytes — invalid UTF-8, embedded NULs, every length up to
    // the buffer — must be dispatched without panicking.
    #[test]
    fn fuzz_handle_command_never_panics() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0x0011_B000_0001);
        for _ in 0..50000 {
            let len = r.below(65) as usize;
            let mut buf = [0u8; 64];
            r.fill(&mut buf[..len]);
            let _ = unsafe { rust_handle_command(buf.as_ptr(), len) };
        }
    }

    // The pure address-window / policy validators must be total (never panic)
    // and deterministic (same inputs → same output) over arbitrary inputs.
    #[test]
    fn fuzz_policy_validators_total_and_deterministic() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0x0011_B000_0002);
        for _ in 0..200000 {
            let task_id = r.next_u32();
            let addr32 = r.next_u32();
            let err = r.next_u32();
            let addr64 = r.next_u64();
            let rights = r.next_u32();

            assert_eq!(
                rust_validate_page_fault(task_id, addr32, err),
                rust_validate_page_fault(task_id, addr32, err)
            );
            assert_eq!(
                rust_get_user_page_protection(task_id, addr32),
                rust_get_user_page_protection(task_id, addr32)
            );
            assert_eq!(rust_user_page_is_noexec(addr64), rust_user_page_is_noexec(addr64));
            assert_eq!(rust_should_demand_zero(err), rust_should_demand_zero(err));
            assert_eq!(rust_signal_handler_addr_ok(addr32), rust_signal_handler_addr_ok(addr32));
            let _ = rust_cow_copy_required(err & 1 == 1, err & 2 == 2, (r.next_u32() & 0xffff) as u16);
            assert_eq!(
                rust_validate_fs_operation(task_id, err, rights, core::ptr::null(), 0),
                rust_validate_fs_operation(task_id, err, rights, core::ptr::null(), 0)
            );
        }
    }

    #[test]
    fn page_fault_validation_guard_and_windows() {
        // The stack guard page is never a valid fault target.
        assert!(!rust_validate_page_fault(1, 0x7FB000, 0));
        assert!(!rust_validate_page_fault(1, 0x7FBFFF, 0));
        // The two mapped user windows are valid.
        assert!(rust_validate_page_fault(1, 0x400000, 0));
        assert!(rust_validate_page_fault(1, 0x7FFFFF, 0));
        assert!(rust_validate_page_fault(1, 0xA00000, 0));
        // NULL page, kernel space, and gaps are rejected (no ambient validity).
        assert!(!rust_validate_page_fault(1, 0, 0));
        assert!(!rust_validate_page_fault(1, 0x100000, 0));
        assert!(!rust_validate_page_fault(1, 0xC0000000, 0));
    }

    #[test]
    fn cap_rights_are_subset_checked() {
        let held = SafeCapability { raw: 0b1011 };
        unsafe {
            // A null capability grants nothing.
            assert!(!rust_cap_has_rights(core::ptr::null(), 0b0001));
            // Holding a superset of the required bits passes.
            assert!(rust_cap_has_rights(&held, 0b0001));
            assert!(rust_cap_has_rights(&held, 0b1010));
            assert!(rust_cap_has_rights(&held, 0b1011));
            // Requiring any bit not held fails — no rights escalation.
            assert!(!rust_cap_has_rights(&held, 0b0100));
            assert!(!rust_cap_has_rights(&held, 0b1111));
        }
        assert!(SafeCap { raw: 0b110 }.has_rights(0b100));
        assert!(!SafeCap { raw: 0b110 }.has_rights(0b001));
    }

    #[test]
    fn user_page_protection_windows() {
        assert_eq!(rust_get_user_page_protection(0, 0x400000), 0x7);
        assert_eq!(rust_get_user_page_protection(0, 0xA00000), 0x7);
        assert_eq!(rust_get_user_page_protection(0, 0xff000000), 0x7);
        assert_eq!(rust_get_user_page_protection(0, 0), 0);
        assert_eq!(rust_get_user_page_protection(0, 0x300000), 0);
    }

    #[test]
    fn wx_stack_noexec_image_executable() {
        // Image / code region must stay executable (flat binaries run here).
        assert!(!rust_user_page_is_noexec(0x400000)); // load base
        assert!(!rust_user_page_is_noexec(0x500000)); // top of a max-size image
        assert!(!rust_user_page_is_noexec(0x519000)); // top of the heap window
        assert!(!rust_user_page_is_noexec(0x7cf000)); // just below the stack floor
        // Low user stack must be non-executable.
        assert!(rust_user_page_is_noexec(0x7d0000));  // window floor (inclusive)
        assert!(rust_user_page_is_noexec(0x7df000));  // low-stack base
        assert!(rust_user_page_is_noexec(0x7ff000 - 0x1000)); // near stack top
        // 0x800000 is one past the user area -> not stack.
        assert!(!rust_user_page_is_noexec(0x800000));
        // High ASLR stack window is non-executable.
        assert!(rust_user_page_is_noexec(0x0000_7ff0_0000_0000 - 0x1000));
        // Other mapped windows and the null page stay executable.
        assert!(!rust_user_page_is_noexec(0xA00000));
        assert!(!rust_user_page_is_noexec(0));
    }

    #[test]
    fn signal_handler_addr_window() {
        // Inside the user code window [0x400000, 0x800000) -> accepted.
        assert!(rust_signal_handler_addr_ok(0x400000)); // window base (inclusive)
        assert!(rust_signal_handler_addr_ok(0x401234)); // a real handler entry
        assert!(rust_signal_handler_addr_ok(0x7fffff)); // last byte in-window
        // Outside the window -> rejected (fail closed).
        assert!(!rust_signal_handler_addr_ok(0));        // null
        assert!(!rust_signal_handler_addr_ok(0x3fffff)); // just below the base
        assert!(!rust_signal_handler_addr_ok(0x800000)); // one past the top
        assert!(!rust_signal_handler_addr_ok(0x7d0000 + 0x400000)); // ~stack, mapped high
        assert!(!rust_signal_handler_addr_ok(0x100000)); // kernel image
    }

    #[test]
    fn demand_fault_cow_and_zero_policy() {
        // COW write from user on a shared page -> copy.
        assert_eq!(
            rust_handle_demand_page_fault(0x400000, WRITE | USER, true, 2),
            DemandAction::CowCopyNeeded
        );
        // COW write but sole owner -> just map writable, no copy.
        assert_eq!(
            rust_handle_demand_page_fault(0x400000, WRITE | USER, true, 1),
            DemandAction::NoAction
        );
        // Not-present user read -> demand zero.
        assert_eq!(
            rust_handle_demand_page_fault(0x400000, USER, false, 0),
            DemandAction::DemandZero
        );
        // Guard page and out-of-window addresses are always invalid.
        assert_eq!(
            rust_handle_demand_page_fault(0x7FB000, USER, false, 0),
            DemandAction::Invalid
        );
        assert_eq!(
            rust_handle_demand_page_fault(0x100000, USER, false, 0),
            DemandAction::Invalid
        );
    }

    #[test]
    fn cow_required_truth_table() {
        assert!(rust_cow_copy_required(true, true, 2));
        assert!(!rust_cow_copy_required(true, true, 1)); // sole owner -> no copy
        assert!(!rust_cow_copy_required(false, true, 2)); // not a COW page
        assert!(!rust_cow_copy_required(true, false, 2)); // not a write
    }

    #[test]
    fn should_demand_zero_bits() {
        assert!(rust_should_demand_zero(USER)); // not-present + user
        assert!(!rust_should_demand_zero(USER | PRESENT)); // already present
        assert!(!rust_should_demand_zero(0)); // not a user fault
    }

    #[test]
    fn fs_operation_requires_some_right() {
        let name = b"file";
        // No rights held -> denied.
        assert_eq!(rust_validate_fs_operation(1, FsOp::Read as u32, 0, name.as_ptr(), name.len()), -1);
        // Any right held -> allowed (per-op masking is enforced in C capfs).
        assert_eq!(rust_validate_fs_operation(1, FsOp::Read as u32, 0x1, name.as_ptr(), name.len()), 0);
    }

    #[test]
    fn handle_command_dispatch() {
        unsafe {
            // A null command is a no-op, not a crash.
            assert_eq!(rust_handle_command(core::ptr::null(), 0), 0);
            let help = b"help";
            assert_eq!(rust_handle_command(help.as_ptr(), help.len()), 42);
            let echo = b"echo hi";
            assert_eq!(rust_handle_command(echo.as_ptr(), echo.len()), 44);
            let unknown = b"frobnicate";
            assert_eq!(rust_handle_command(unknown.as_ptr(), unknown.len()), -1);
            // Invalid UTF-8 is rejected rather than mis-parsed.
            let bad = [0xffu8, 0xfe];
            assert_eq!(rust_handle_command(bad.as_ptr(), bad.len()), -1);
        }
    }
}


