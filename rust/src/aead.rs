//! Authenticated encryption for the kernel's encryption-at-rest (storage) layer.
//!
//! Construction: **Encrypt-then-MAC** composing two primitives that already
//! live in this crate and are validated against their RFC known-answer vectors:
//!   * confidentiality — ChaCha20 (RFC 8439), from `crate::rng`,
//!   * integrity       — HMAC-SHA256 (RFC 2104), from `crate::sha256`.
//!
//! This deliberately introduces **no new primitive cryptography**: it is the
//! standard, provably-secure generic composition (Encrypt-then-MAC with
//! independent keys) over building blocks the kernel already trusts. It
//! replaces the previous in-kernel "AES" (a non-AES homebrew permutation with a
//! broken key schedule) and the deterministic-nonce CTR mode that reused
//! keystream across rewrites.
//!
//! Usage contract:
//!   * `enc_key` (32B) and `mac_key` (32B) MUST be independent — derive them
//!     from one secret via HKDF with distinct output ranges, never reuse one as
//!     both.
//!   * `nonce` (12B) MUST be unique per (enc_key) encryption. The storage layer
//!     draws a fresh CSPRNG nonce on every write and stores it beside the tag,
//!     so (key, nonce) never repeats even when a block is overwritten.
//!   * `aad` binds context (e.g. inode/block numbers) into the tag without
//!     encrypting it; the same `aad` must be supplied to `open`.
//!
//! Tag: the 16-byte (128-bit) prefix of HMAC-SHA256 — the same strength class
//! as AES-GCM / ChaCha20-Poly1305 tags.

use crate::rng::chacha20_block;
use crate::sha256::Sha256Hmac;

pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

/// XOR `buf` in place with the ChaCha20 keystream for (key, nonce), block
/// counter starting at 0. Encryption and decryption are the same operation.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut off = 0usize;
    while off < buf.len() {
        let ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        let take = core::cmp::min(64, buf.len() - off);
        for i in 0..take {
            buf[off + i] ^= ks[i];
        }
        off += take;
    }
}

/// Tag = HMAC-SHA256(mac_key, nonce ‖ aad ‖ ciphertext)[..16].
/// Streamed so no contiguous nonce+aad+ct buffer is ever allocated.
fn compute_tag(mac_key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; AEAD_TAG_LEN] {
    let mut mac = Sha256Hmac::new(mac_key);
    mac.update(nonce);
    mac.update(aad);
    mac.update(ct);
    let full = mac.finalize();
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&full[..AEAD_TAG_LEN]);
    tag
}

/// Constant-time tag comparison: no secret-dependent early exit.
fn tags_equal(a: &[u8; AEAD_TAG_LEN], b: &[u8; AEAD_TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..AEAD_TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    // Keep the accumulator opaque so the compiler can't reintroduce a branch.
    core::hint::black_box(diff) == 0
}

/// Encrypt `buf` in place (Encrypt-then-MAC) and produce the tag.
fn seal(enc_key: &[u8; 32], mac_key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; AEAD_TAG_LEN] {
    chacha20_xor(enc_key, nonce, buf);
    compute_tag(mac_key, nonce, aad, buf)
}

/// Verify the tag (constant-time) and, only on success, decrypt `buf` in place.
/// Returns true if authentic. On failure `buf` is zeroed and left undecrypted.
fn open(enc_key: &[u8; 32], mac_key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; AEAD_TAG_LEN]) -> bool {
    let expect = compute_tag(mac_key, nonce, aad, buf);
    if !tags_equal(&expect, tag) {
        for b in buf.iter_mut() {
            *b = 0;
        }
        return false;
    }
    chacha20_xor(enc_key, nonce, buf);
    true
}

// ---------------------------------------------------------------------------
// FFI surface used by the C storage layer.
// ---------------------------------------------------------------------------

/// Seal `buf` (len bytes) in place: ChaCha20 encrypt then HMAC.
/// `enc_key`/`mac_key` are 32 bytes each, `nonce` 12 bytes, `tag_out` 16 bytes.
/// Returns 0 on success, -1 on bad arguments.
///
/// # Safety
/// All pointers must be valid for their stated lengths and non-overlapping with
/// each other (except that `buf` is read and written). `enc_key`/`mac_key` are
/// 32 bytes, `nonce` 12 bytes, `tag_out` 16 bytes, `aad` is `aad_len` bytes
/// (may be null iff `aad_len == 0`), and `buf` is `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_aead_seal(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    buf: *mut u8,
    len: usize,
    tag_out: *mut u8,
) -> i32 {
    if enc_key.is_null() || mac_key.is_null() || nonce.is_null() || tag_out.is_null() {
        return -1;
    }
    if buf.is_null() && len != 0 {
        return -1;
    }
    if aad.is_null() && aad_len != 0 {
        return -1;
    }
    let mut ek = [0u8; 32];
    let mut mk = [0u8; 32];
    let mut nc = [0u8; AEAD_NONCE_LEN];
    ek.copy_from_slice(core::slice::from_raw_parts(enc_key, 32));
    mk.copy_from_slice(core::slice::from_raw_parts(mac_key, 32));
    nc.copy_from_slice(core::slice::from_raw_parts(nonce, AEAD_NONCE_LEN));
    let aad_s = if aad_len == 0 { &[][..] } else { core::slice::from_raw_parts(aad, aad_len) };
    let buf_s = if len == 0 { &mut [][..] } else { core::slice::from_raw_parts_mut(buf, len) };

    let tag = seal(&ek, &mk, &nc, aad_s, buf_s);
    core::ptr::copy_nonoverlapping(tag.as_ptr(), tag_out, AEAD_TAG_LEN);
    0
}

/// Open `buf` (len bytes of ciphertext) in place: verify HMAC (constant-time),
/// then decrypt only if authentic. Returns 0 on success; -1 on auth failure or
/// bad arguments (and on auth failure `buf` is zeroed).
///
/// # Safety
/// Same pointer/length contract as [`rust_aead_seal`]; `tag` is 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_aead_open(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    buf: *mut u8,
    len: usize,
    tag: *const u8,
) -> i32 {
    if enc_key.is_null() || mac_key.is_null() || nonce.is_null() || tag.is_null() {
        return -1;
    }
    if buf.is_null() && len != 0 {
        return -1;
    }
    if aad.is_null() && aad_len != 0 {
        return -1;
    }
    let mut ek = [0u8; 32];
    let mut mk = [0u8; 32];
    let mut nc = [0u8; AEAD_NONCE_LEN];
    let mut tg = [0u8; AEAD_TAG_LEN];
    ek.copy_from_slice(core::slice::from_raw_parts(enc_key, 32));
    mk.copy_from_slice(core::slice::from_raw_parts(mac_key, 32));
    nc.copy_from_slice(core::slice::from_raw_parts(nonce, AEAD_NONCE_LEN));
    tg.copy_from_slice(core::slice::from_raw_parts(tag, AEAD_TAG_LEN));
    let aad_s = if aad_len == 0 { &[][..] } else { core::slice::from_raw_parts(aad, aad_len) };
    let buf_s = if len == 0 { &mut [][..] } else { core::slice::from_raw_parts_mut(buf, len) };

    if open(&ek, &mk, &nc, aad_s, buf_s, &tg) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic *test* vectors, derived via the crate's SHA-256 from domain
    // labels rather than hard-coded key/nonce bytes. They must be fixed so the
    // round-trip and tamper tests are reproducible, but they never occur in the
    // production path: real enc/mac keys are HKDF-SHA256 subkeys and the nonce is
    // a fresh CSPRNG draw, all supplied by the C storage layer through the
    // rust_aead_seal / rust_aead_open FFI (which take caller-provided key
    // pointers — this crate hard-codes no key material anywhere).
    fn keys() -> ([u8; 32], [u8; 32], [u8; AEAD_NONCE_LEN]) {
        let ek: [u8; 32] = crate::sha256::sha256(b"horus/aead-test/enc-key");
        let mk: [u8; 32] = crate::sha256::sha256(b"horus/aead-test/mac-key");
        let nh = crate::sha256::sha256(b"horus/aead-test/nonce");
        let nc: [u8; AEAD_NONCE_LEN] = core::array::from_fn(|i| nh[i]);
        (ek, mk, nc)
    }

    #[test]
    fn seal_then_open_roundtrip() {
        let (ek, mk, nc) = keys();
        let aad = b"inode=7,block=3";
        let plain = *b"the quick brown fox jumps over the lazy dog!!";
        let mut buf = plain;
        let tag = seal(&ek, &mk, &nc, aad, &mut buf);
        // Ciphertext must differ from plaintext.
        assert_ne!(buf, plain);
        // Authentic open restores the plaintext.
        assert!(open(&ek, &mk, &nc, aad, &mut buf, &tag));
        assert_eq!(buf, plain);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (ek, mk, nc) = keys();
        let aad = b"ctx";
        let mut buf = *b"sensitive block contents here..";
        let tag = seal(&ek, &mk, &nc, aad, &mut buf);
        buf[0] ^= 0x01; // flip one ciphertext bit
        assert!(!open(&ek, &mk, &nc, aad, &mut buf, &tag));
        // Rejected plaintext must not leak: buffer is zeroed on failure.
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let (ek, mk, nc) = keys();
        let aad = b"ctx";
        let mut buf = *b"another block of plaintext bytes";
        let mut tag = seal(&ek, &mk, &nc, aad, &mut buf);
        tag[AEAD_TAG_LEN - 1] ^= 0x80;
        assert!(!open(&ek, &mk, &nc, aad, &mut buf, &tag));
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let (ek, mk, nc) = keys();
        let mut buf = *b"bound-to-context payload bytes!!";
        let tag = seal(&ek, &mk, &nc, b"inode=1", &mut buf);
        // Same key/nonce/ciphertext but different AAD must fail authentication.
        assert!(!open(&ek, &mk, &nc, b"inode=2", &mut buf, &tag));
    }

    #[test]
    fn nonce_separation_changes_keystream() {
        let (ek, mk, mut nc) = keys();
        let plain = *b"0123456789abcdef0123456789abcdef";
        let mut a = plain;
        let _ = seal(&ek, &mk, &nc, b"", &mut a);
        nc[0] ^= 0xFF;
        let mut b = plain;
        let _ = seal(&ek, &mk, &nc, b"", &mut b);
        // Different nonce => different keystream => different ciphertext.
        assert_ne!(a, b);
    }

    // ---- property/differential fuzz (zero-dependency; see rust/src/fuzzrng.rs) ----

    // Random keys/nonce/aad/plaintext of random lengths: an authentic open after
    // seal always recovers the exact plaintext, and neither seal nor open panics.
    #[test]
    fn fuzz_seal_open_roundtrip() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0xAEAD_0001);
        for _ in 0..20000 {
            let mut ek = [0u8; 32];
            let mut mk = [0u8; 32];
            let mut nc = [0u8; AEAD_NONCE_LEN];
            r.fill(&mut ek);
            r.fill(&mut mk);
            r.fill(&mut nc);
            let plen = r.below(65) as usize;
            let mut plain = [0u8; 64];
            r.fill(&mut plain[..plen]);
            let alen = r.below(33) as usize;
            let mut aad = [0u8; 32];
            r.fill(&mut aad[..alen]);

            let mut buf = plain;
            let tag = seal(&ek, &mk, &nc, &aad[..alen], &mut buf[..plen]);
            assert!(open(&ek, &mk, &nc, &aad[..alen], &mut buf[..plen], &tag));
            assert_eq!(buf[..plen], plain[..plen]);
        }
    }

    // Every single-bit mutation of a MAC-covered input (mac_key, nonce, aad,
    // ciphertext, or tag) must make open fail closed and zero the buffer. enc_key
    // is deliberately excluded: it is not in the MAC (HMAC over nonce‖aad‖ct), so
    // corrupting it authenticates but decrypts to garbage — an Encrypt-then-MAC
    // property, not a defect.
    #[test]
    fn fuzz_open_fails_closed_on_mac_covered_mutation() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0xAEAD_0002);
        for _ in 0..20000 {
            let mut ek = [0u8; 32];
            let mut mk = [0u8; 32];
            let mut nc = [0u8; AEAD_NONCE_LEN];
            r.fill(&mut ek);
            r.fill(&mut mk);
            r.fill(&mut nc);
            let plen = 1 + r.below(64) as usize; // >=1 so the ciphertext arm is live
            let mut plain = [0u8; 64];
            r.fill(&mut plain[..plen]);
            let alen = 1 + r.below(31) as usize; // >=1 so the aad arm is live
            let mut aad = [0u8; 32];
            r.fill(&mut aad[..alen]);

            let mut ct = plain;
            let tag = seal(&ek, &mk, &nc, &aad[..alen], &mut ct[..plen]);

            let mut mk2 = mk;
            let mut nc2 = nc;
            let mut aad2 = aad;
            let mut ct2 = ct;
            let mut tag2 = tag;
            match r.below(5) {
                0 => mk2[r.below(32) as usize] ^= 1u8 << r.below(8),
                1 => nc2[r.below(AEAD_NONCE_LEN as u32) as usize] ^= 1u8 << r.below(8),
                2 => aad2[r.below(alen as u32) as usize] ^= 1u8 << r.below(8),
                3 => ct2[r.below(plen as u32) as usize] ^= 1u8 << r.below(8),
                _ => tag2[r.below(AEAD_TAG_LEN as u32) as usize] ^= 1u8 << r.below(8),
            }

            let mut dec = ct2;
            let ok = open(&ek, &mk2, &nc2, &aad2[..alen], &mut dec[..plen], &tag2);
            assert!(!ok, "single-bit mutation of a MAC-covered input must fail closed");
            assert!(
                dec[..plen].iter().all(|&b| b == 0),
                "a rejected plaintext must be zeroed, not leaked"
            );
        }
    }

    // Random garbage handed to open must never authenticate and never panic.
    #[test]
    fn fuzz_open_rejects_random_garbage() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0xAEAD_0003);
        let mut authed = 0u64;
        for _ in 0..20000 {
            let mut ek = [0u8; 32];
            let mut mk = [0u8; 32];
            let mut nc = [0u8; AEAD_NONCE_LEN];
            let mut tag = [0u8; AEAD_TAG_LEN];
            r.fill(&mut ek);
            r.fill(&mut mk);
            r.fill(&mut nc);
            r.fill(&mut tag);
            let plen = r.below(65) as usize;
            let mut buf = [0u8; 64];
            r.fill(&mut buf[..plen]);
            let alen = r.below(33) as usize;
            let mut aad = [0u8; 32];
            r.fill(&mut aad[..alen]);
            if open(&ek, &mk, &nc, &aad[..alen], &mut buf[..plen], &tag) {
                authed += 1;
            }
        }
        assert_eq!(authed, 0, "a random 16-byte tag must not authenticate");
    }
}
