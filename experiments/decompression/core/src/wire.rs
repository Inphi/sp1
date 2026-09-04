//! Explicit 4-byte-aligned request/result encoding for decompression measurements.

use alloc::vec::Vec;
use core::fmt;
use crate::lz77::Lz77Token;

const REQUEST_MAGIC: u32 = 0x4443_5031; // DCP1
const RESULT_MAGIC: u32 = 0x4443_5231; // DCR1
const VERSION: u32 = 1;
const REQUEST_WORDS: usize = 16;
const RESULT_WORDS: usize = 20;

pub const FLAG_VERIFY_OUTPUT_LEN: u32 = 1 << 0;
pub const FLAG_VERIFY_CHECKSUM: u32 = 1 << 1;
pub const RESULT_FLAG_RUNTIME_SECTIONS_ALIGNED: u32 = 1 << 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BenchMode {
    ZlibReference = 1,
    DeflateReference = 2,
    BrotliReference = 3,
    Passthrough = 4,
    AdlerScalar = 5,
    AdlerBatched = 6,
    Lz77Verify = 7,
    ZlibTrace = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Codec { None = 0, Zlib = 1, Deflate = 2, Brotli = 3 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BenchStatus {
    Success = 0,
    InvalidRequest = 1,
    DecodeError = 2,
    OutputLimitExceeded = 3,
    OutputLengthMismatch = 4,
    ChecksumMismatch = 5,
    WitnessMismatch = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum WireErrorKind {
    TooShort = 1,
    BadHeader = 2,
    UnknownMode = 3,
    UnknownCodec = 4,
    TruncatedSection = 5,
    LengthOverflow = 6,
    BadTokenSection = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError { pub kind: WireErrorKind, pub detail: u32 }
impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "wire {:?} ({})", self.kind, self.detail) }
}
#[cfg(feature = "std")]
impl std::error::Error for WireError {}

#[derive(Clone, Copy, Debug)]
pub struct BenchRequest<'a> {
    pub mode: BenchMode,
    pub codec: Codec,
    pub flags: u32,
    pub max_output: u32,
    pub max_distance: u32,
    pub expected_output_len: u32,
    pub expected_checksum: u32,
    pub payload: &'a [u8],
    pub output: &'a [u8],
    pub literals: &'a [u8],
    token_bytes: &'a [u8],
}

impl<'a> BenchRequest<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, WireError> {
        if bytes.len() < REQUEST_WORDS * 4 { return Err(err(WireErrorKind::TooShort, bytes.len())); }
        if word(bytes, 0)? != REQUEST_MAGIC || word(bytes, 4)? != VERSION {
            return Err(err(WireErrorKind::BadHeader, 0));
        }
        let mode = BenchMode::try_from(word(bytes, 8)?)?;
        let codec = Codec::try_from(word(bytes, 12)?)?;
        let flags = word(bytes, 16)?;
        let max_output = word(bytes, 20)?;
        let max_distance = word(bytes, 24)?;
        let expected_output_len = word(bytes, 28)?;
        let expected_checksum = word(bytes, 32)?;
        let payload_len = word(bytes, 36)? as usize;
        let output_len = word(bytes, 40)? as usize;
        let literals_len = word(bytes, 44)? as usize;
        let token_count = word(bytes, 48)? as usize;
        let token_len = token_count.checked_mul(12).ok_or_else(|| err(WireErrorKind::LengthOverflow, token_count))?;
        let mut offset = REQUEST_WORDS * 4;
        let payload = section(bytes, &mut offset, payload_len)?;
        let output = section(bytes, &mut offset, output_len)?;
        let literals = section(bytes, &mut offset, literals_len)?;
        let token_bytes = section(bytes, &mut offset, token_len)?;
        if offset != bytes.len() { return Err(err(WireErrorKind::BadHeader, bytes.len() - offset)); }
        Ok(Self { mode, codec, flags, max_output, max_distance, expected_output_len, expected_checksum, payload, output, literals, token_bytes })
    }

    pub fn runtime_alignment_ok(&self) -> bool {
        fn aligned(s: &[u8]) -> bool { s.is_empty() || (s.as_ptr() as usize) % 4 == 0 }
        aligned(self.payload) && aligned(self.output) && aligned(self.literals) && aligned(self.token_bytes)
    }

    pub fn tokens(&self) -> Result<Vec<Lz77Token>, WireError> {
        if self.token_bytes.len() % 12 != 0 { return Err(err(WireErrorKind::BadTokenSection, self.token_bytes.len())); }
        let mut out = Vec::with_capacity(self.token_bytes.len() / 12);
        for chunk in self.token_bytes.chunks_exact(12) {
            out.push(Lz77Token {
                kind: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                len: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
                distance: u32::from_le_bytes(chunk[8..12].try_into().unwrap()),
            });
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchResult {
    pub status: BenchStatus,
    pub mode: BenchMode,
    pub codec: Codec,
    pub runtime_flags: u32,
    pub output_len: u32,
    pub checksum: u32,
    pub literal_bytes: u32,
    pub match_bytes: u32,
    pub token_count: u32,
    pub blocks: u32,
    pub symbols: u32,
    pub extra_bits: u32,
    pub table_slots: u32,
    pub compressed_bits: u32,
    pub error_offset: u32,
    pub detail: u32,
}

impl BenchResult {
    pub const fn empty(status: BenchStatus, mode: BenchMode, codec: Codec) -> Self {
        Self { status, mode, codec, runtime_flags: 0, output_len: 0, checksum: 0, literal_bytes: 0, match_bytes: 0, token_count: 0, blocks: 0, symbols: 0, extra_bits: 0, table_slots: 0, compressed_bits: 0, error_offset: 0, detail: 0 }
    }

    pub fn encode(&self) -> Vec<u8> {
        let words = [RESULT_MAGIC, VERSION, self.status as u32, self.mode as u32, self.codec as u32, self.runtime_flags, self.output_len, self.checksum, self.literal_bytes, self.match_bytes, self.token_count, self.blocks, self.symbols, self.extra_bits, self.table_slots, self.compressed_bits, self.error_offset, self.detail, 0, 0];
        let mut out = Vec::with_capacity(RESULT_WORDS * 4);
        for w in words { out.extend_from_slice(&w.to_le_bytes()); }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != RESULT_WORDS * 4 { return Err(err(WireErrorKind::TooShort, bytes.len())); }
        if word(bytes, 0)? != RESULT_MAGIC || word(bytes, 4)? != VERSION { return Err(err(WireErrorKind::BadHeader, 0)); }
        Ok(Self {
            status: BenchStatus::try_from(word(bytes, 8)?)?, mode: BenchMode::try_from(word(bytes, 12)?)?, codec: Codec::try_from(word(bytes, 16)?)?, runtime_flags: word(bytes, 20)?, output_len: word(bytes, 24)?, checksum: word(bytes, 28)?, literal_bytes: word(bytes, 32)?, match_bytes: word(bytes, 36)?, token_count: word(bytes, 40)?, blocks: word(bytes, 44)?, symbols: word(bytes, 48)?, extra_bits: word(bytes, 52)?, table_slots: word(bytes, 56)?, compressed_bits: word(bytes, 60)?, error_offset: word(bytes, 64)?, detail: word(bytes, 68)?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn encode_request(
    mode: BenchMode, codec: Codec, flags: u32, max_output: u32, max_distance: u32,
    expected_output_len: u32, expected_checksum: u32, payload: &[u8], output: &[u8], literals: &[u8], tokens: &[Lz77Token],
) -> Vec<u8> {
    let words = [REQUEST_MAGIC, VERSION, mode as u32, codec as u32, flags, max_output, max_distance, expected_output_len, expected_checksum, payload.len() as u32, output.len() as u32, literals.len() as u32, tokens.len() as u32, 0, 0, 0];
    let mut out = Vec::new();
    for w in words { out.extend_from_slice(&w.to_le_bytes()); }
    append_section(&mut out, payload);
    append_section(&mut out, output);
    append_section(&mut out, literals);
    for token in tokens {
        out.extend_from_slice(&token.kind.to_le_bytes());
        out.extend_from_slice(&token.len.to_le_bytes());
        out.extend_from_slice(&token.distance.to_le_bytes());
    }
    while out.len() % 4 != 0 { out.push(0); }
    out
}

fn append_section(out: &mut Vec<u8>, bytes: &[u8]) { out.extend_from_slice(bytes); while out.len() % 4 != 0 { out.push(0); } }
fn section<'a>(bytes: &'a [u8], offset: &mut usize, logical_len: usize) -> Result<&'a [u8], WireError> {
    let end = offset.checked_add(logical_len).ok_or_else(|| err(WireErrorKind::LengthOverflow, logical_len))?;
    if end > bytes.len() { return Err(err(WireErrorKind::TruncatedSection, end)); }
    let result = &bytes[*offset..end];
    let padded = (end + 3) & !3;
    if padded > bytes.len() { return Err(err(WireErrorKind::TruncatedSection, padded)); }
    *offset = padded;
    Ok(result)
}
fn word(bytes: &[u8], offset: usize) -> Result<u32, WireError> {
    let slice = bytes.get(offset..offset + 4).ok_or_else(|| err(WireErrorKind::TooShort, offset + 4))?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}
fn err(kind: WireErrorKind, detail: usize) -> WireError { WireError { kind, detail: u32::try_from(detail).unwrap_or(u32::MAX) } }

macro_rules! enum_try {
    ($ty:ty, $kind:expr, {$($n:expr => $v:path),+ $(,)?}) => { impl TryFrom<u32> for $ty { type Error = WireError; fn try_from(value: u32) -> Result<Self, Self::Error> { match value { $($n => Ok($v),)+ _ => Err(WireError { kind: $kind, detail: value }) } } } };
}
enum_try!(BenchMode, WireErrorKind::UnknownMode, {1=>BenchMode::ZlibReference,2=>BenchMode::DeflateReference,3=>BenchMode::BrotliReference,4=>BenchMode::Passthrough,5=>BenchMode::AdlerScalar,6=>BenchMode::AdlerBatched,7=>BenchMode::Lz77Verify,8=>BenchMode::ZlibTrace});
enum_try!(Codec, WireErrorKind::UnknownCodec, {0=>Codec::None,1=>Codec::Zlib,2=>Codec::Deflate,3=>Codec::Brotli});
enum_try!(BenchStatus, WireErrorKind::BadHeader, {0=>BenchStatus::Success,1=>BenchStatus::InvalidRequest,2=>BenchStatus::DecodeError,3=>BenchStatus::OutputLimitExceeded,4=>BenchStatus::OutputLengthMismatch,5=>BenchStatus::ChecksumMismatch,6=>BenchStatus::WitnessMismatch});

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_round_trip_and_alignment() {
        let tokens = [Lz77Token::literal(3), Lz77Token::match_copy(6, 3)];
        let bytes = encode_request(BenchMode::Lz77Verify, Codec::Zlib, 0, 1024, 32768, 9, 0, b"abcde", b"abcabcabc", b"abc", &tokens);
        let req = BenchRequest::decode(&bytes).unwrap();
        assert_eq!(req.payload, b"abcde");
        assert_eq!(req.tokens().unwrap(), tokens);
        assert!(req.runtime_alignment_ok());
    }
}
