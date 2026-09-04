#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod adler32;
pub mod deflate;
pub mod lz77;
pub mod prefix;
pub mod wire;

/// Saturating conversion used by benchmark counters that are serialized as u32.
#[inline]
pub fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
