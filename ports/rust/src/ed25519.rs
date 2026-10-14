//! Ed25519 signature verification (RFC 8032), verify only, written for this port.
//!
//! It has not been independently audited. It passes the RFC 8032 test vectors and the shared
//! vectors in spec/conformance/ed25519.json. It verifies public data, so it makes no attempt at
//! constant time.
//!
//! `verify` applies the engine's own pre-checks first (spec/SEMANTICS.md, "Signatures"): lower-case
//! hex of the right length and S < L. Then it decodes A and R, rejecting a y coordinate >= p and
//! points that are not on the curve (no square root, or x = 0 with the sign bit set), and checks the
//! cofactorless equation [S]B == R + [k]A with k = SHA-512(R || A || M) mod L.
use crate::sha512;
use std::sync::OnceLock;

// ------------------------------------------------------------------ field arithmetic mod p = 2^255 - 19
// Five 51-bit limbs, little-endian. Products use u128.

#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

const MASK: u64 = (1 << 51) - 1;

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_u64(x: u64) -> Fe {
        Fe([x & MASK, x >> 51, 0, 0, 0])
    }

    /// The low 255 bits of `b` (little-endian); the top bit is ignored.
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let w = |i: usize| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[8 * i..8 * i + 8]);
            u64::from_le_bytes(x)
        };
        let (w0, w1, w2, w3) = (w(0), w(1), w(2), w(3));
        Fe([
            w0 & MASK,
            ((w0 >> 51) | (w1 << 13)) & MASK,
            ((w1 >> 38) | (w2 << 26)) & MASK,
            ((w2 >> 25) | (w3 << 39)) & MASK,
            (w3 >> 12) & MASK,
        ])
    }

    /// Carry so every limb is below 2^51 plus a little (the value is unchanged mod p).
    fn carry(mut self) -> Fe {
        let l = &mut self.0;
        let mut c;
        c = l[0] >> 51;
        l[0] &= MASK;
        l[1] += c;
        c = l[1] >> 51;
        l[1] &= MASK;
        l[2] += c;
        c = l[2] >> 51;
        l[2] &= MASK;
        l[3] += c;
        c = l[3] >> 51;
        l[3] &= MASK;
        l[4] += c;
        c = l[4] >> 51;
        l[4] &= MASK;
        l[0] += c * 19;
        self
    }

    fn add(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + o.0[i];
        }
        Fe(r).carry()
    }

    fn sub(&self, o: &Fe) -> Fe {
        // self + 4p - o; inputs are carried, so limbs are below 2^52 and nothing underflows.
        const FOUR_P: [u64; 5] = [(MASK - 18) * 4, MASK * 4, MASK * 4, MASK * 4, MASK * 4];
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + FOUR_P[i] - o.0[i];
        }
        Fe(r).carry()
    }

    fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(&self, o: &Fe) -> Fe {
        let a = self.0.map(|x| x as u128);
        let b = o.0.map(|x| x as u128);
        let b19: [u128; 5] = b.map(|x| x * 19);
        let r0 = a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1];
        let r1 = a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2];
        let r2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3];
        let r3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4];
        let r4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];
        let m = MASK as u128;
        let mut c;
        let mut l = [0u64; 5];
        c = r0 >> 51;
        l[0] = (r0 & m) as u64;
        let r1 = r1 + c;
        c = r1 >> 51;
        l[1] = (r1 & m) as u64;
        let r2 = r2 + c;
        c = r2 >> 51;
        l[2] = (r2 & m) as u64;
        let r3 = r3 + c;
        c = r3 >> 51;
        l[3] = (r3 & m) as u64;
        let r4 = r4 + c;
        c = r4 >> 51;
        l[4] = (r4 & m) as u64;
        let l0 = l[0] as u128 + c * 19;
        l[0] = (l0 & m) as u64;
        l[1] += (l0 >> 51) as u64;
        Fe(l).carry()
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    /// self^e, e given as 32 little-endian bytes (square and multiply, variable time).
    fn pow(&self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    fn invert(&self) -> Fe {
        // p - 2 = 2^255 - 21
        let mut e = [0xffu8; 32];
        e[0] = 0xeb;
        e[31] = 0x7f;
        self.pow(&e)
    }

    /// The unique representative in [0, p), little-endian.
    fn to_bytes(&self) -> [u8; 32] {
        let mut h = self.carry().carry().0;
        // Now h < 2^255 + small; subtract p when h >= p.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        let mut c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        c = h[1] >> 51;
        h[1] &= MASK;
        h[2] += c;
        c = h[2] >> 51;
        h[2] &= MASK;
        h[3] += c;
        c = h[3] >> 51;
        h[3] &= MASK;
        h[4] += c;
        h[4] &= MASK;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0;
        let mut k = 0;
        for limb in h {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 {
                out[k] = acc as u8;
                acc >>= 8;
                bits -= 8;
                k += 1;
            }
        }
        if k < 32 {
            out[k] = acc as u8;
        }
        out
    }

    fn eq(&self, o: &Fe) -> bool {
        self.to_bytes() == o.to_bytes()
    }

    fn is_zero(&self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    fn is_odd(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

// ------------------------------------------------------------------ points in extended coordinates

#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

struct Consts {
    d2: Fe,      // 2 * d
    d: Fe,       // -121665 / 121666
    sqrt_m1: Fe, // 2^((p-1)/4)
    base: Point,
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        let d = Fe::from_u64(121665).neg().mul(&Fe::from_u64(121666).invert());
        // (p - 1) / 4 = 2^253 - 5
        let mut e = [0xffu8; 32];
        e[0] = 0xfb;
        e[31] = 0x1f;
        let sqrt_m1 = Fe::from_u64(2).pow(&e);
        let mut c = Consts { d2: d.add(&d), d, sqrt_m1, base: IDENTITY };
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        c.base = decompress_with(&c, &b).expect("the base point decodes");
        c
    })
}

const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

impl Point {
    /// Unified addition (RFC 8032, section 5.1.4); also correct for doubling.
    fn add(&self, o: &Point) -> Point {
        let c = consts();
        let a = self.y.sub(&self.x).mul(&o.y.sub(&o.x));
        let b = self.y.add(&self.x).mul(&o.y.add(&o.x));
        let cc = self.t.mul(&c.d2).mul(&o.t);
        let dd = self.z.add(&self.z).mul(&o.z);
        let e = b.sub(&a);
        let f = dd.sub(&cc);
        let g = dd.add(&cc);
        let h = b.add(&a);
        Point { x: e.mul(&f), y: g.mul(&h), t: e.mul(&h), z: f.mul(&g) }
    }

    /// [s]P for a 32-byte little-endian scalar (double and add, variable time).
    fn mul(&self, s: &[u8; 32]) -> Point {
        let mut r = IDENTITY;
        for i in (0..256).rev() {
            r = r.add(&r);
            if (s[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }

    fn equals(&self, o: &Point) -> bool {
        self.x.mul(&o.z).eq(&o.x.mul(&self.z)) && self.y.mul(&o.z).eq(&o.y.mul(&self.z))
    }
}

/// p = 2^255 - 19 as 32 little-endian bytes.
fn y_is_canonical(b: &[u8; 32]) -> bool {
    let mut y = *b;
    y[31] &= 0x7f;
    // y < p unless y is p .. 2^255 - 1: bytes 1..=30 are 0xff, byte 31 is 0x7f and byte 0 >= 0xed.
    !(y[31] == 0x7f && y[1..31].iter().all(|&x| x == 0xff) && y[0] >= 0xed)
}

/// Decode a point (RFC 8032, section 5.1.3). None for a non-canonical y or a point not on the curve.
fn decompress_with(c: &Consts, b: &[u8; 32]) -> Option<Point> {
    if !y_is_canonical(b) {
        return None;
    }
    let sign = (b[31] >> 7) == 1;
    let y = Fe::from_bytes(b);
    let yy = y.square();
    let u = yy.sub(&Fe::ONE);
    let v = c.d.mul(&yy).add(&Fe::ONE);
    // x = u v^3 (u v^7)^((p-5)/8)
    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut e = [0xffu8; 32];
    e[0] = 0xfd;
    e[31] = 0x0f; // (p - 5) / 8 = 2^252 - 3
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow(&e));
    let vxx = v.mul(&x.square());
    if vxx.eq(&u) {
        // x is a square root
    } else if vxx.eq(&u.neg()) {
        x = x.mul(&c.sqrt_m1);
    } else {
        return None;
    }
    if x.is_zero() && sign {
        return None;
    }
    if x.is_odd() != sign {
        x = x.neg();
    }
    Some(Point { x, y, z: Fe::ONE, t: x.mul(&y) })
}

// ------------------------------------------------------------------ scalars mod L

/// L = 2^252 + 27742317777372353535851937790883648493, as four little-endian u64 words.
const L: [u64; 4] = [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0x0000000000000000, 0x1000000000000000];

fn ge_l(r: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if r[i] != L[i] {
            return r[i] > L[i];
        }
    }
    true
}

fn sub_l(r: &mut [u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = r[i].overflowing_sub(L[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 || b2) as u64;
    }
}

/// A little-endian byte string reduced mod L (bit by bit: r = 2r + bit, minus L when r >= L).
fn reduce_mod_l(bytes: &[u8]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for i in (0..bytes.len() * 8).rev() {
        // r < L < 2^253, so 2r + 1 fits in 256 bits.
        r[3] = (r[3] << 1) | (r[2] >> 63);
        r[2] = (r[2] << 1) | (r[1] >> 63);
        r[1] = (r[1] << 1) | (r[0] >> 63);
        r[0] = (r[0] << 1) | ((bytes[i / 8] >> (i % 8)) & 1) as u64;
        if ge_l(&r) {
            sub_l(&mut r);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

fn scalar_below_l(s: &[u8; 32]) -> bool {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut x = [0u8; 8];
        x.copy_from_slice(&s[8 * i..8 * i + 8]);
        r[i] = u64::from_le_bytes(x);
    }
    !ge_l(&r)
}

// ------------------------------------------------------------------ hex and verify

/// `s` is exactly `n` lower-case hex characters.
pub fn is_lower_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A public key: 64 lower-case hex characters.
pub fn is_key_hex(s: &str) -> bool {
    is_lower_hex(s, 64)
}

/// Decode hex (either case); None when malformed.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes().chunks(2).map(|p| Some(v(p[0])? << 4 | v(p[1])?)).collect()
}

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// True only for a valid signature `sig_hex` (128 lower-case hex) by `public_hex` (64 lower-case hex)
/// over `message`. Never panics: every malformed input is false.
pub fn verify(public_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    if !is_key_hex(public_hex) || !is_lower_hex(sig_hex, 128) {
        return false;
    }
    let (Some(pk), Some(sig)) = (hex_decode(public_hex), hex_decode(sig_hex)) else {
        return false;
    };
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&pk);
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if !scalar_below_l(&s) {
        return false;
    }
    let c = consts();
    let (Some(a), Some(r)) = (decompress_with(c, &a_bytes), decompress_with(c, &r_bytes)) else {
        return false;
    };
    let mut h = Vec::with_capacity(64 + message.len());
    h.extend_from_slice(&r_bytes);
    h.extend_from_slice(&a_bytes);
    h.extend_from_slice(message);
    let k = reduce_mod_l(&sha512::digest(&h));
    let lhs = c.base.mul(&s);
    let rhs = r.add(&a.mul(&k));
    lhs.equals(&rhs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032, section 7.1, tests 1 to 3.
    const RFC: [(&str, &str, &str); 3] = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc8032_vectors() {
        for (pk, msg, sig) in RFC {
            assert!(verify(pk, &hex_decode(msg).unwrap(), sig), "{}", pk);
        }
    }

    #[test]
    fn rejects_changes() {
        let (pk, _, sig) = RFC[1];
        assert!(!verify(pk, b"s", sig));
        let mut bad = sig.to_string();
        bad.replace_range(0..1, "a");
        assert!(!verify(pk, &[0x72], &bad));
        assert!(!verify(pk, &[0x72], &sig.to_uppercase()));
        assert!(!verify(&pk.to_uppercase(), &[0x72], sig));
        assert!(!verify(pk, &[0x72], &sig[..126]));
        assert!(!verify(&pk[..62], &[0x72], sig));
        assert!(!verify("zz", &[0x72], sig));
    }

    #[test]
    fn rejects_s_plus_l() {
        let (pk, msg, sig) = RFC[0];
        let raw = hex_decode(sig).unwrap();
        let mut s = [0u64; 4];
        for i in 0..4 {
            let mut x = [0u8; 8];
            x.copy_from_slice(&raw[32 + 8 * i..40 + 8 * i]);
            s[i] = u64::from_le_bytes(x);
        }
        let mut carry = 0u128;
        for i in 0..4 {
            let t = s[i] as u128 + L[i] as u128 + carry;
            s[i] = t as u64;
            carry = t >> 64;
        }
        let mut forged = raw[..32].to_vec();
        for w in s {
            forged.extend_from_slice(&w.to_le_bytes());
        }
        assert!(!verify(pk, &hex_decode(msg).unwrap(), &hex_encode(&forged)));
    }

    #[test]
    fn rejects_bad_points() {
        let (_, msg, sig) = RFC[0];
        let m = hex_decode(msg).unwrap();
        // y = p (non-canonical encoding of y = 0).
        let p = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        assert!(!verify(p, &m, sig));
        // y = 1, x = 0 with the sign bit set.
        let neg_zero = "0100000000000000000000000000000000000000000000000000000000000080";
        assert!(!verify(neg_zero, &m, sig));
        // y = 2 is not on the curve.
        let off = "0200000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify(off, &m, sig));
    }

    #[test]
    fn scalar_reduction() {
        let mut l = Vec::new();
        for w in L {
            l.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(reduce_mod_l(&l), [0u8; 32]);
        let mut l1 = l.clone();
        l1[0] += 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(reduce_mod_l(&l1), one);
        assert!(!scalar_below_l(&l.clone().try_into().unwrap()));
    }

    /// Time of one verify: cargo test --offline --release -- --ignored --nocapture verify_timing
    #[test]
    #[ignore]
    fn verify_timing() {
        let (pk, msg, sig) = RFC[2];
        let m = hex_decode(msg).unwrap();
        assert!(verify(pk, &m, sig));
        let n = 200;
        let t = std::time::Instant::now();
        for _ in 0..n {
            assert!(verify(pk, &m, sig));
        }
        println!("one Ed25519 verify: {:.3} ms", t.elapsed().as_secs_f64() * 1000.0 / n as f64);
    }

    #[test]
    fn field_inverse() {
        let x = Fe::from_u64(123456789);
        assert!(x.mul(&x.invert()).eq(&Fe::ONE));
        assert!(consts().sqrt_m1.square().eq(&Fe::ONE.neg()));
    }
}
