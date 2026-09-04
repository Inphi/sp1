//! Codec-agnostic LZ77 witness verification.
//!
//! Literal tokens consume bytes from a separate literal witness. Match tokens
//! prove that bytes already present in the claimed output repeat at `distance`.
//! Overlap is intentionally allowed.

use core::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Lz77Token {
    pub kind: u32,
    pub len: u32,
    pub distance: u32,
}

impl Lz77Token {
    pub const LITERAL: u32 = 0;
    pub const MATCH: u32 = 1;
    pub const fn literal(len: u32) -> Self { Self { kind: Self::LITERAL, len, distance: 0 } }
    pub const fn match_copy(len: u32, distance: u32) -> Self { Self { kind: Self::MATCH, len, distance } }
    pub const fn is_literal(&self) -> bool { self.kind == Self::LITERAL }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lz77Stats {
    pub tokens: u64,
    pub literal_bytes: u64,
    pub match_bytes: u64,
    pub output_bytes: u64,
    pub max_match_len: u32,
    pub max_distance: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Lz77ErrorKind {
    UnknownToken = 1,
    ZeroLength = 2,
    LiteralWitnessExhausted = 3,
    LiteralWitnessTrailing = 4,
    OutputExhausted = 5,
    OutputTrailing = 6,
    OutputMismatch = 7,
    DistanceZero = 8,
    DistanceExceedsOutput = 9,
    DistanceExceedsLimit = 10,
    SizeOverflow = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lz77Error {
    pub kind: Lz77ErrorKind,
    pub output_offset: u32,
    pub detail: u32,
}

impl fmt::Display for Lz77Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LZ77 {:?} at output {} ({})", self.kind, self.output_offset, self.detail)
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Lz77Error {}

pub fn verify_lz77(
    output: &[u8],
    literals: &[u8],
    tokens: &[Lz77Token],
    max_distance: u32,
) -> Result<Lz77Stats, Lz77Error> {
    let mut out = 0usize;
    let mut lit = 0usize;
    let mut stats = Lz77Stats::default();
    for token in tokens {
        stats.tokens += 1;
        let len = token.len as usize;
        if len == 0 { return Err(err(Lz77ErrorKind::ZeroLength, out, token.kind as usize)); }
        match token.kind {
            Lz77Token::LITERAL => {
                let lit_end = lit.checked_add(len).ok_or_else(|| err(Lz77ErrorKind::SizeOverflow, out, len))?;
                let out_end = out.checked_add(len).ok_or_else(|| err(Lz77ErrorKind::SizeOverflow, out, len))?;
                if lit_end > literals.len() { return Err(err(Lz77ErrorKind::LiteralWitnessExhausted, out, lit_end)); }
                if out_end > output.len() { return Err(err(Lz77ErrorKind::OutputExhausted, out, out_end)); }
                if output[out..out_end] != literals[lit..lit_end] {
                    let rel = output[out..out_end].iter().zip(&literals[lit..lit_end]).position(|(a,b)| a != b).unwrap_or(0);
                    return Err(err(Lz77ErrorKind::OutputMismatch, out + rel, literals[lit + rel] as usize));
                }
                out = out_end;
                lit = lit_end;
                stats.literal_bytes += token.len as u64;
            }
            Lz77Token::MATCH => {
                let distance = token.distance as usize;
                if distance == 0 { return Err(err(Lz77ErrorKind::DistanceZero, out, 0)); }
                if token.distance > max_distance { return Err(err(Lz77ErrorKind::DistanceExceedsLimit, out, distance)); }
                if distance > out { return Err(err(Lz77ErrorKind::DistanceExceedsOutput, out, distance)); }
                let out_end = out.checked_add(len).ok_or_else(|| err(Lz77ErrorKind::SizeOverflow, out, len))?;
                if out_end > output.len() { return Err(err(Lz77ErrorKind::OutputExhausted, out, out_end)); }
                for i in 0..len {
                    if output[out + i] != output[out + i - distance] {
                        return Err(err(Lz77ErrorKind::OutputMismatch, out + i, distance));
                    }
                }
                out = out_end;
                stats.match_bytes += token.len as u64;
                stats.max_match_len = stats.max_match_len.max(token.len);
                stats.max_distance = stats.max_distance.max(token.distance);
            }
            _ => return Err(err(Lz77ErrorKind::UnknownToken, out, token.kind as usize)),
        }
    }
    if lit != literals.len() { return Err(err(Lz77ErrorKind::LiteralWitnessTrailing, out, literals.len() - lit)); }
    if out != output.len() { return Err(err(Lz77ErrorKind::OutputTrailing, out, output.len() - out)); }
    stats.output_bytes = output.len() as u64;
    Ok(stats)
}

fn err(kind: Lz77ErrorKind, output_offset: usize, detail: usize) -> Lz77Error {
    Lz77Error {
        kind,
        output_offset: u32::try_from(output_offset).unwrap_or(u32::MAX),
        detail: u32::try_from(detail).unwrap_or(u32::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap() {
        let output = b"abcabcabcabc";
        let tokens = [Lz77Token::literal(3), Lz77Token::match_copy(9, 3)];
        let stats = verify_lz77(output, b"abc", &tokens, 32_768).unwrap();
        assert_eq!(stats.match_bytes, 9);
    }
    #[test]
    fn rejects_bad_witness() {
        let output = b"aaaaab";
        let tokens = [Lz77Token::literal(1), Lz77Token::match_copy(5, 1)];
        assert_eq!(verify_lz77(output, b"a", &tokens, 32_768).unwrap_err().kind, Lz77ErrorKind::OutputMismatch);
    }
}
