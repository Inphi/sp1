#![no_main]
sp1_zkvm::entrypoint!(main);

use std::io::Read;
use sp1_decompression_core::{
    adler32::{adler32_batched, adler32_scalar}, deflate::trace_zlib, lz77::verify_lz77,
    saturating_u32,
    wire::{BenchMode, BenchRequest, BenchResult, BenchStatus, Codec, FLAG_VERIFY_CHECKSUM, FLAG_VERIFY_OUTPUT_LEN, RESULT_FLAG_RUNTIME_SECTIONS_ALIGNED},
};

pub fn main() {
    let bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let result = match BenchRequest::decode(&bytes) {
        Ok(request) => execute(&request),
        Err(error) => { let mut r=BenchResult::empty(BenchStatus::InvalidRequest,BenchMode::Passthrough,Codec::None); r.detail=error.kind as u32; r }
    };
    sp1_zkvm::io::commit(&result.encode());
}

fn execute(request: &BenchRequest<'_>) -> BenchResult {
    let mut result=BenchResult::empty(BenchStatus::Success,request.mode,request.codec);
    if request.runtime_alignment_ok(){result.runtime_flags|=RESULT_FLAG_RUNTIME_SECTIONS_ALIGNED;}
    match request.mode {
        BenchMode::ZlibReference=>match miniz_oxide::inflate::decompress_to_vec_zlib(request.payload){Ok(o)=>fill_output(&mut result,request,&o),Err(_)=>result.status=BenchStatus::DecodeError},
        BenchMode::DeflateReference=>match miniz_oxide::inflate::decompress_to_vec(request.payload){Ok(o)=>fill_output(&mut result,request,&o),Err(_)=>result.status=BenchStatus::DecodeError},
        BenchMode::BrotliReference=>{let mut d=brotli::Decompressor::new(request.payload,4096);let mut o=Vec::new();match d.by_ref().take(u64::from(request.max_output)+1).read_to_end(&mut o){Ok(_)=>fill_output(&mut result,request,&o),Err(_)=>result.status=BenchStatus::DecodeError}},
        BenchMode::Passthrough=>fill_output(&mut result,request,request.payload),
        BenchMode::AdlerScalar=>{result.output_len=u32_len(request.payload.len());result.checksum=adler32_scalar(request.payload);validate(&mut result,request)},
        BenchMode::AdlerBatched=>{result.output_len=u32_len(request.payload.len());result.checksum=adler32_batched(request.payload);validate(&mut result,request)},
        BenchMode::Lz77Verify=>match request.tokens(){
            Ok(tokens)=>match verify_lz77(request.output,request.literals,&tokens,request.max_distance){
                Ok(s)=>{result.output_len=saturating_u32(s.output_bytes);result.literal_bytes=saturating_u32(s.literal_bytes);result.match_bytes=saturating_u32(s.match_bytes);result.token_count=saturating_u32(s.tokens);result.checksum=adler32_batched(request.output);validate(&mut result,request)},
                Err(e)=>{result.status=BenchStatus::WitnessMismatch;result.error_offset=e.output_offset;result.detail=e.kind as u32}
            },
            Err(e)=>{result.status=BenchStatus::InvalidRequest;result.detail=e.kind as u32}
        },
        BenchMode::ZlibTrace=>match trace_zlib(request.payload,request.max_output as usize){
            Ok(t)=>{result.output_len=u32_len(t.output.len());result.checksum=t.adler32.unwrap_or_else(||adler32_batched(&t.output));result.literal_bytes=saturating_u32(t.stats.literal_bytes);result.match_bytes=saturating_u32(t.stats.match_bytes);result.token_count=u32_len(t.tokens.len());result.blocks=saturating_u32(t.stats.blocks);result.symbols=saturating_u32(t.stats.symbols);result.extra_bits=saturating_u32(t.stats.extra_bits);result.table_slots=saturating_u32(t.stats.table_slots);result.compressed_bits=saturating_u32(t.stats.compressed_bits);validate(&mut result,request)},
            Err(e)=>{result.status=if e.kind==sp1_decompression_core::deflate::DeflateErrorKind::OutputLimitExceeded{BenchStatus::OutputLimitExceeded}else{BenchStatus::DecodeError};result.error_offset=e.bit_offset;result.detail=e.kind as u32}
        },
    }
    result
}

fn fill_output(r:&mut BenchResult,q:&BenchRequest<'_>,o:&[u8]){if o.len()>q.max_output as usize{r.status=BenchStatus::OutputLimitExceeded;r.output_len=u32_len(o.len());return;}r.output_len=u32_len(o.len());r.checksum=adler32_batched(o);validate(r,q)}
fn validate(r:&mut BenchResult,q:&BenchRequest<'_>){if r.status!=BenchStatus::Success{return;}if q.flags&FLAG_VERIFY_OUTPUT_LEN!=0&&r.output_len!=q.expected_output_len{r.status=BenchStatus::OutputLengthMismatch;r.detail=q.expected_output_len;}else if q.flags&FLAG_VERIFY_CHECKSUM!=0&&r.checksum!=q.expected_checksum{r.status=BenchStatus::ChecksumMismatch;r.detail=q.expected_checksum;}}
fn u32_len(v:usize)->u32{u32::try_from(v).unwrap_or(u32::MAX)}
