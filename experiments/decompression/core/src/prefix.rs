//! Canonical prefix-code helpers for the Phase-2 verify-don't-compute boundary.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CanonicalCode {
    pub code: u32,
    pub len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PrefixErrorKind {
    CodeLengthTooLarge = 1,
    Oversubscribed = 2,
    Empty = 3,
    SymbolOutOfRange = 4,
    LengthMismatch = 5,
    BitRange = 6,
    CodeMismatch = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixError {
    pub kind: PrefixErrorKind,
    pub symbol: u32,
    pub detail: u32,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix {:?} symbol={} detail={}", self.kind, self.symbol, self.detail)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrefixError {}

/// Build canonical codes. When `reverse_for_lsb_stream` is true the low `len`
/// bits are reversed to match DEFLATE's LSB-first bit packing.
pub fn canonical_codes(
    lengths: &[u8],
    max_len: u8,
    reverse_for_lsb_stream: bool,
) -> Result<Vec<CanonicalCode>, PrefixError> {
    let mut counts = vec![0u32; usize::from(max_len) + 1];
    let mut nonzero = 0usize;
    for (symbol, &len) in lengths.iter().enumerate() {
        if len > max_len {
            return Err(perr(PrefixErrorKind::CodeLengthTooLarge, symbol, len as usize));
        }
        if len != 0 {
            counts[usize::from(len)] += 1;
            nonzero += 1;
        }
    }
    if nonzero == 0 {
        return Err(perr(PrefixErrorKind::Empty, 0, 0));
    }

    let mut left = 1i64;
    for bits in 1..=usize::from(max_len) {
        left = (left << 1) - i64::from(counts[bits]);
        if left < 0 {
            return Err(perr(PrefixErrorKind::Oversubscribed, 0, bits));
        }
    }

    let mut next = vec![0u32; usize::from(max_len) + 1];
    let mut code = 0u32;
    for bits in 1..=usize::from(max_len) {
        code = (code + counts[bits - 1]) << 1;
        next[bits] = code;
    }

    let mut result = vec![CanonicalCode::default(); lengths.len()];
    for (symbol, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let index = usize::from(len);
        let assigned = next[index];
        next[index] += 1;
        result[symbol] = CanonicalCode {
            code: if reverse_for_lsb_stream { reverse_low_bits(assigned, len) } else { assigned },
            len,
        };
    }
    Ok(result)
}

/// Verify a claimed symbol at an arbitrary bit offset without decoding a tree.
pub fn verify_symbol_at(
    input: &[u8],
    bit_offset: u32,
    symbol: u32,
    claimed_len: u8,
    codes: &[CanonicalCode],
) -> Result<(), PrefixError> {
    let entry = codes.get(symbol as usize).ok_or_else(|| perr(PrefixErrorKind::SymbolOutOfRange, symbol as usize, codes.len()))?;
    if entry.len == 0 || entry.len != claimed_len {
        return Err(perr(PrefixErrorKind::LengthMismatch, symbol as usize, claimed_len as usize));
    }
    let bits = read_low_bits(input, bit_offset as usize, claimed_len)
        .ok_or_else(|| perr(PrefixErrorKind::BitRange, symbol as usize, bit_offset as usize))?;
    if bits != entry.code {
        return Err(perr(PrefixErrorKind::CodeMismatch, symbol as usize, bits as usize));
    }
    Ok(())
}

#[inline]
pub fn reverse_low_bits(value: u32, len: u8) -> u32 {
    if len == 0 { 0 } else { value.reverse_bits() >> (32 - u32::from(len)) }
}

#[inline]
pub fn read_low_bits(input: &[u8], bit_offset: usize, len: u8) -> Option<u32> {
    if len > 24 { return None; }
    let end = bit_offset.checked_add(usize::from(len))?;
    if end > input.len().checked_mul(8)? { return None; }
    let mut value = 0u32;
    for i in 0..usize::from(len) {
        let pos = bit_offset + i;
        value |= u32::from((input[pos / 8] >> (pos % 8)) & 1) << i;
    }
    Some(value)
}

#[inline]
fn perr(kind: PrefixErrorKind, symbol: usize, detail: usize) -> PrefixError {
    PrefixError { kind, symbol: u32::try_from(symbol).unwrap_or(u32::MAX), detail: u32::try_from(detail).unwrap_or(u32::MAX) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_deflate_style_codes() {
        let codes = canonical_codes(&[2, 1, 3, 3], 3, true).unwrap();
        assert_eq!(codes[1].len, 1);
        assert_ne!(codes[0].len, 0);
    }

    #[test]
    fn rejects_oversubscribed_set() {
        assert_eq!(canonical_codes(&[1, 1, 1], 1, true).unwrap_err().kind, PrefixErrorKind::Oversubscribed);
    }
}
