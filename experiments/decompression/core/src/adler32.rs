//! Adler-32 baselines. The batched version preserves the exact RFC-1950 result
//! while reducing the frequency of modulo operations.

const MOD_ADLER: u32 = 65_521;
const NMAX: usize = 5_552;

#[inline]
pub fn adler32_scalar(bytes: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in bytes {
        a += u32::from(byte);
        if a >= MOD_ADLER {
            a -= MOD_ADLER;
        }
        b += a;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

/// zlib-style batched Adler-32. NMAX bounds the sums so u32 arithmetic cannot
/// overflow before the reduction.
#[inline]
pub fn adler32_batched(bytes: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = rest.len().min(NMAX);
        for &byte in &rest[..n] {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
        rest = &rest[n..];
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(adler32_scalar(b""), 1);
        assert_eq!(adler32_scalar(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(adler32_batched(b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn scalar_matches_batched_across_nmax() {
        let bytes: alloc::vec::Vec<u8> = (0..12_000).map(|i| (i * 31) as u8).collect();
        assert_eq!(adler32_scalar(&bytes), adler32_batched(&bytes));
    }
}
