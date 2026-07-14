//! Ed25519 signature **verification** (RFC 8032), from scratch in safe `no_std`
//! Rust and validated against the RFC 8032 §7.1 known-answer vectors.
//!
//! Only verification is implemented — the kernel never signs; a release is
//! signed offline / in CI with the private key, and the kernel holds only the
//! public key. Every input to verification (public key, signature, message) is
//! public, so the arithmetic here is deliberately straightforward rather than
//! constant-time: there is no secret whose timing could leak.
//!
//! Field: GF(2^255-19), radix-2^51 limbs. Group: the Edwards curve, extended
//! (X:Y:Z:T) coordinates with the complete a=-1 addition law, so the same
//! formula serves adds and doublings. Scalars are reduced mod the group order L
//! by plain bitwise long division (verification runs a handful of times, so
//! clarity beats speed).

use crate::sha512::Sha512;

const MASK: u64 = (1u64 << 51) - 1;

#[inline]
fn load64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// ---- Field element GF(2^255-19), radix 2^51 -------------------------------

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

// Exponents (little-endian) used for field powers.
const P_MINUS_2: [u8; 32] = {
    // 2^255 - 21  (inverse: a^(p-2))
    let mut e = [0xffu8; 32];
    e[0] = 0xeb;
    e[31] = 0x7f;
    e
};
const P_MINUS_5_DIV_8: [u8; 32] = {
    // (p-5)/8 = 2^252 - 3  (square-root candidate exponent, RFC 8032 §5.1.3)
    let mut e = [0xffu8; 32];
    e[0] = 0xfd;
    e[31] = 0x0f;
    e
};
const P_MINUS_1_DIV_4: [u8; 32] = {
    // (p-1)/4 = 2^253 - 5  (sqrt(-1) = 2^((p-1)/4))
    let mut e = [0xffu8; 32];
    e[0] = 0xfb;
    e[31] = 0x1f;
    e
};

impl Fe {
    fn zero() -> Fe { Fe([0; 5]) }
    fn one() -> Fe { Fe([1, 0, 0, 0, 0]) }
    fn small(v: u64) -> Fe { Fe([v & MASK, v >> 51, 0, 0, 0]) }

    /// Load a field element from 32 little-endian bytes (bit 255 ignored).
    fn from_bytes(s: &[u8; 32]) -> Fe {
        let h0 = load64(&s[0..8]) & MASK;
        let h1 = (load64(&s[6..14]) >> 3) & MASK;
        let h2 = (load64(&s[12..20]) >> 6) & MASK;
        let h3 = (load64(&s[19..27]) >> 1) & MASK;
        let h4 = (load64(&s[24..32]) >> 12) & MASK;
        Fe([h0, h1, h2, h3, h4])
    }

    /// Carry-propagate five u128 limbs into a reduced Fe (limbs < 2^51 + 1).
    #[inline]
    fn reduce(t: [u128; 5]) -> Fe {
        let m = (1u128 << 51) - 1;
        let mut c = t;
        let mut carry;
        carry = c[0] >> 51; c[0] &= m; c[1] += carry;
        carry = c[1] >> 51; c[1] &= m; c[2] += carry;
        carry = c[2] >> 51; c[2] &= m; c[3] += carry;
        carry = c[3] >> 51; c[3] &= m; c[4] += carry;
        carry = c[4] >> 51; c[4] &= m; c[0] += 19 * carry;
        // one more light pass (only c0 could exceed 51 bits now)
        carry = c[0] >> 51; c[0] &= m; c[1] += carry;
        Fe([c[0] as u64, c[1] as u64, c[2] as u64, c[3] as u64, c[4] as u64])
    }

    fn add(&self, o: &Fe) -> Fe {
        let a = self.0; let b = o.0;
        Fe::reduce([
            a[0] as u128 + b[0] as u128,
            a[1] as u128 + b[1] as u128,
            a[2] as u128 + b[2] as u128,
            a[3] as u128 + b[3] as u128,
            a[4] as u128 + b[4] as u128,
        ])
    }

    fn sub(&self, o: &Fe) -> Fe {
        // add 2p (per-limb) then subtract; inputs are reduced so no underflow.
        let a = self.0; let b = o.0;
        Fe::reduce([
            (a[0] + 0xFFFFFFFFFFFDA - b[0]) as u128,
            (a[1] + 0xFFFFFFFFFFFFE - b[1]) as u128,
            (a[2] + 0xFFFFFFFFFFFFE - b[2]) as u128,
            (a[3] + 0xFFFFFFFFFFFFE - b[3]) as u128,
            (a[4] + 0xFFFFFFFFFFFFE - b[4]) as u128,
        ])
    }

    fn mul(&self, o: &Fe) -> Fe {
        let a = self.0; let b = o.0;
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let c0 = m(a[0], b[0]) + 19 * (m(a[1], b[4]) + m(a[2], b[3]) + m(a[3], b[2]) + m(a[4], b[1]));
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + 19 * (m(a[2], b[4]) + m(a[3], b[3]) + m(a[4], b[2]));
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + 19 * (m(a[3], b[4]) + m(a[4], b[3]));
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + 19 * m(a[4], b[4]);
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        Fe::reduce([c0, c1, c2, c3, c4])
    }

    fn sq(&self) -> Fe { self.mul(self) }

    fn pow(&self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::one();
        for i in (0..256).rev() {
            r = r.sq();
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    fn invert(&self) -> Fe { self.pow(&P_MINUS_2) }

    fn neg(&self) -> Fe { Fe::zero().sub(self) }

    /// Fully reduce mod p and emit 32 little-endian bytes (canonical).
    fn to_bytes(self) -> [u8; 32] {
        // Carry to reduced form.
        let m = MASK;
        let mut h = self.0;
        let mut carry;
        carry = h[0] >> 51; h[0] &= m; h[1] += carry;
        carry = h[1] >> 51; h[1] &= m; h[2] += carry;
        carry = h[2] >> 51; h[2] &= m; h[3] += carry;
        carry = h[3] >> 51; h[3] &= m; h[4] += carry;
        carry = h[4] >> 51; h[4] &= m; h[0] += 19 * carry;
        carry = h[0] >> 51; h[0] &= m; h[1] += carry;
        // Conditional subtract p: q = 1 iff h >= p.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        // Propagate the carry from the +19 across the limbs; masking h[0] here
        // (before reading its carry) would drop it and leave a value >= p
        // unreduced — the q==1 (value in [p, 2^255)) path.
        let mut carry2;
        carry2 = h[0] >> 51; h[0] &= m; h[1] += carry2;
        carry2 = h[1] >> 51; h[1] &= m; h[2] += carry2;
        carry2 = h[2] >> 51; h[2] &= m; h[3] += carry2;
        carry2 = h[3] >> 51; h[3] &= m; h[4] += carry2;
        h[4] &= m; // drop the 2^255 bit that q accounted for
        // Pack 5x51-bit limbs into 32 bytes.
        let mut s = [0u8; 32];
        let v = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        for i in 0..4 {
            s[i * 8..i * 8 + 8].copy_from_slice(&v[i].to_le_bytes());
        }
        s
    }

    fn equals(&self, o: &Fe) -> bool { self.to_bytes() == o.to_bytes() }
    fn is_zero(&self) -> bool { self.to_bytes() == [0u8; 32] }
    fn is_negative(&self) -> bool { self.to_bytes()[0] & 1 == 1 }
}

fn fe_d() -> Fe {
    // d = -121665/121666
    Fe::small(121665).neg().mul(&Fe::small(121666).invert())
}
fn fe_k2d() -> Fe { let d = fe_d(); d.add(&d) }
fn fe_sqrtm1() -> Fe { Fe::small(2).pow(&P_MINUS_1_DIV_4) }

// ---- Group element, extended coordinates (X:Y:Z:T), a=-1 ------------------

#[derive(Clone, Copy)]
struct Ge { x: Fe, y: Fe, z: Fe, t: Fe }

impl Ge {
    fn identity() -> Ge { Ge { x: Fe::zero(), y: Fe::one(), z: Fe::one(), t: Fe::zero() } }

    /// Complete a=-1 addition (Hisil–Wong–Carter–Dawson); unified for doubling.
    fn add(&self, q: &Ge) -> Ge {
        let a = self.y.sub(&self.x).mul(&q.y.sub(&q.x));
        let b = self.y.add(&self.x).mul(&q.y.add(&q.x));
        let c = self.t.mul(&fe_k2d()).mul(&q.t);
        let d = self.z.mul(&q.z).mul(&Fe::small(2));
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Ge { x: e.mul(&f), y: g.mul(&h), z: f.mul(&g), t: e.mul(&h) }
    }

    fn neg(&self) -> Ge { Ge { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() } }

    /// [s]self for a 32-byte little-endian scalar s (double-and-add, MSB first).
    fn scalarmult(&self, s: &[u8; 32]) -> Ge {
        let mut r = Ge::identity();
        for i in (0..256).rev() {
            r = r.add(&r);
            if (s[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }

    /// Affine compression to 32 little-endian bytes (y with x's sign in bit 255).
    fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut s = y.to_bytes();
        s[31] |= (x.is_negative() as u8) << 7;
        s
    }
}

/// Decompress a 32-byte point encoding, or None if it is not a canonical point.
fn decompress(bytes: &[u8; 32]) -> Option<Ge> {
    let sign = (bytes[31] >> 7) & 1;
    let mut yb = *bytes;
    yb[31] &= 0x7f;
    let y = Fe::from_bytes(&yb);
    // Reject non-canonical y (>= p): to_bytes reduces mod p, so a mismatch means
    // the input encoded a value in [p, 2^255).
    if y.to_bytes() != yb {
        return None;
    }
    let one = Fe::one();
    let yy = y.sq();
    let u = yy.sub(&one);
    let v = yy.mul(&fe_d()).add(&one);
    let v3 = v.sq().mul(&v);
    let v7 = v3.sq().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow(&P_MINUS_5_DIV_8));
    let vxx = v.mul(&x.sq());
    if vxx.equals(&u) {
        // x is a root
    } else if vxx.equals(&u.neg()) {
        x = x.mul(&fe_sqrtm1());
    } else {
        return None;
    }
    if x.is_zero() && sign == 1 {
        return None;
    }
    if (x.is_negative() as u8) != sign {
        x = x.neg();
    }
    let t = x.mul(&y);
    Some(Ge { x, y, z: Fe::one(), t })
}

// ---- Scalar helpers (mod group order L) -----------------------------------

// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// s < L, both 32-byte little-endian.
fn scalar_below_l(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] < L[i] { return true; }
        if s[i] > L[i] { return false; }
    }
    false // equal is not below
}

/// 64-byte little-endian value mod L, returned as a 32-byte little-endian scalar.
/// Bitwise long division (MSB first); the remainder stays < L < 2^253.
fn reduce_mod_l(hash: &[u8; 64]) -> [u8; 32] {
    let mut rem = [0u8; 32];
    for i in (0..512).rev() {
        // rem <<= 1
        let mut carry = 0u8;
        for byte in rem.iter_mut() {
            let nb = (*byte << 1) | carry;
            carry = *byte >> 7;
            *byte = nb;
        }
        // rem |= bit i of hash
        rem[0] |= (hash[i / 8] >> (i % 8)) & 1;
        // if rem >= L: rem -= L
        if !scalar_below_l(&rem) {
            let mut borrow = 0i16;
            for j in 0..32 {
                let d = rem[j] as i16 - L[j] as i16 - borrow;
                if d < 0 { rem[j] = (d + 256) as u8; borrow = 1; }
                else { rem[j] = d as u8; borrow = 0; }
            }
        }
    }
    rem
}

fn base_point() -> Option<Ge> {
    // Standard Ed25519 base point, compressed (y = 4/5, x even).
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    decompress(&b)
}

/// Verify an Ed25519 signature. Returns true iff `sig` (64 bytes: R||S) is a
/// valid signature by `public_key` (32 bytes) over `msg`.
pub fn verify(public_key: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
    let a = match decompress(public_key) { Some(a) => a, None => return false };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[0..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..64]);
    // Reject a non-canonical S (malleability guard): S must be < L.
    if !scalar_below_l(&s_bytes) {
        return false;
    }
    let base = match base_point() { Some(b) => b, None => return false };

    // k = SHA512(R || A || M) mod L
    let mut h = Sha512::new();
    h.update(&r_bytes);
    h.update(public_key);
    h.update(msg);
    let hash = h.finalize();
    let k = reduce_mod_l(&hash);

    // Accept iff [S]B - [k]A encodes back to R.
    let sb = base.scalarmult(&s_bytes);
    let ka = a.scalarmult(&k);
    let rprime = sb.add(&ka.neg());
    rprime.compress() == r_bytes
}

// ---- FFI surface used by the C kernel --------------------------------------

/// Verify an Ed25519 signature over `msg[0..msg_len]`.
///
/// # Safety
/// `public_key` must point to 32 readable bytes, `sig` to 64, and `msg` to
/// `msg_len` bytes (or be null iff `msg_len == 0`). Returns 1 if the signature
/// is valid, 0 otherwise (including any null/invalid pointer).
#[no_mangle]
pub unsafe extern "C" fn rust_ed25519_verify(
    public_key: *const u8,
    sig: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if public_key.is_null() || sig.is_null() || (msg.is_null() && msg_len != 0) {
        return 0;
    }
    let mut pk = [0u8; 32];
    core::ptr::copy_nonoverlapping(public_key, pk.as_mut_ptr(), 32);
    let mut s = [0u8; 64];
    core::ptr::copy_nonoverlapping(sig, s.as_mut_ptr(), 64);
    let m: &[u8] = if msg_len == 0 { &[] } else { core::slice::from_raw_parts(msg, msg_len) };
    verify(&pk, &s, m) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let b = s.as_bytes();
        let mut out = [0u8; N];
        let nyb = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        };
        for i in 0..N {
            out[i] = (nyb(b[2 * i]) << 4) | nyb(b[2 * i + 1]);
        }
        out
    }

    #[test]
    fn field_inverse_roundtrip() {
        let a = Fe::small(123456789);
        let one = a.mul(&a.invert());
        assert_eq!(one.to_bytes(), Fe::one().to_bytes());
        // also a couple of direct field identities
        assert_eq!(Fe::small(2).mul(&Fe::small(3)).to_bytes(), Fe::small(6).to_bytes());
        assert_eq!(Fe::small(5).invert().mul(&Fe::small(5)).to_bytes(), Fe::one().to_bytes());
    }

    #[test]
    fn base_point_decompresses() {
        assert!(base_point().is_some(), "standard base point must decompress");
    }

    // RFC 8032 §7.1 TEST 1 (empty message).
    #[test]
    fn rfc8032_test1_empty_message() {
        let pk: [u8; 32] = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig: [u8; 64] = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assert!(verify(&pk, &sig, &[]));
    }

    // RFC 8032 §7.1 TEST 2 (one-byte message 0x72).
    #[test]
    fn rfc8032_test2_one_byte() {
        let pk: [u8; 32] = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let msg = [0x72u8];
        let sig: [u8; 64] = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(verify(&pk, &sig, &msg));
    }

    #[test]
    fn rejects_tampered_message() {
        let pk: [u8; 32] = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig: [u8; 64] = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(!verify(&pk, &sig, &[0x73u8]), "a flipped message byte must fail");
    }

    #[test]
    fn rejects_tampered_signature() {
        let pk: [u8; 32] = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let mut sig: [u8; 64] = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        sig[0] ^= 1;
        assert!(!verify(&pk, &sig, &[0x72u8]), "a flipped signature byte must fail");
    }

    // Cross-implementation validation: a signature produced by OpenSSL 3.x
    // (reference implementation) over an 85-byte payload must verify here. This
    // is the exact vector embedded in the verified-boot self-test.
    #[test]
    fn openssl_generated_vector_verifies() {
        let pk: [u8; 32] = unhex("4dc901356b992013678f0295d97a9089d7ab5fd9affcffa2bd3460360c83cbe9");
        let sig: [u8; 64] = unhex(
            "5240f2e717bb4c132e001e80a48de3dd034c6a5f3e91e618f219fb28ca675e3c872a7fa73830ce210e3891d51f1573c9392c28f3fef590ef775d2e55cfac2107");
        let msg = b"Horus verified-boot anchor v1: this signed manifest authorizes the kernel to proceed.";
        assert!(verify(&pk, &sig, msg));
        // And a one-byte tamper of the payload must be rejected.
        let mut bad = *msg;
        bad[0] ^= 1;
        assert!(!verify(&pk, &sig, &bad));
    }

    #[test]
    fn rejects_wrong_key() {
        let pk: [u8; 32] = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig: [u8; 64] = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(!verify(&pk, &sig, &[0x72u8]), "valid sig under the wrong key must fail");
    }

    // ---- property/differential fuzz (zero-dependency; see rust/src/fuzzrng.rs) ----

    // Arbitrary 32-byte keys, 64-byte signatures, and messages must never panic
    // the verifier (non-curve-point decompression, non-canonical y-coordinates,
    // arbitrary scalar S past the group order) and must fail closed.
    #[test]
    fn fuzz_verify_never_panics_and_rejects_garbage() {
        use crate::fuzzrng::SplitMix64;
        let mut r = SplitMix64::new(0xED25_0001_0001);
        let mut accepted = 0u64;
        for _ in 0..600 {
            let mut pk = [0u8; 32];
            let mut sig = [0u8; 64];
            r.fill(&mut pk);
            r.fill(&mut sig);
            let mlen = r.below(97) as usize;
            let mut msg = [0u8; 96];
            r.fill(&mut msg[..mlen]);
            if verify(&pk, &sig, &msg[..mlen]) {
                accepted += 1;
            }
        }
        // A random (key, signature) verifying a random message is astronomically
        // unlikely; any acceptance would indicate a broken check.
        assert_eq!(accepted, 0, "random garbage must not verify");
    }

    // Differential: a genuinely valid (key, signature, message) triple must be
    // rejected under every single-bit mutation of any of the three.
    #[test]
    fn fuzz_mutated_valid_triple_always_rejected() {
        use crate::fuzzrng::SplitMix64;
        let pk: [u8; 32] = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig: [u8; 64] = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        let msg = [0x72u8];
        assert!(verify(&pk, &sig, &msg), "baseline vector must verify");
        let mut r = SplitMix64::new(0x00ED_2519_0002);
        for _ in 0..800 {
            let mut pk2 = pk;
            let mut sig2 = sig;
            let mut msg2 = msg;
            match r.below(3) {
                0 => pk2[r.below(32) as usize] ^= 1u8 << r.below(8),
                1 => sig2[r.below(64) as usize] ^= 1u8 << r.below(8),
                _ => msg2[0] ^= 1u8 << r.below(8),
            }
            assert!(
                !verify(&pk2, &sig2, &msg2),
                "a single-bit-mutated valid triple must never verify"
            );
        }
    }
}
