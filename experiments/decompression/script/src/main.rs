use std::{env, fs, process, time::Instant};

use sp1_decompression_core::{
    adler32::adler32_batched,
    deflate::trace_zlib,
    wire::{encode_request, BenchMode, BenchResult, Codec, FLAG_VERIFY_CHECKSUM, FLAG_VERIFY_OUTPUT_LEN},
};
use sp1_sdk::{include_elf, prelude::*, Elf, ProverClient, SP1Stdin};

const ELF: Elf = include_elf!("sp1-decompression-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 { usage(); }
    let mode_name=&args[1]; let input_path=&args[2];
    let max_output=args.get(3).and_then(|s|s.parse::<u32>().ok()).unwrap_or(32*1024*1024);
    let prove=args.iter().any(|a|a=="--prove");
    let input=fs::read(input_path).unwrap_or_else(|e|panic!("failed to read {input_path}: {e}"));
    let request=build_request(mode_name,&input,max_output);
    let mut stdin=SP1Stdin::new(); stdin.write(&request);
    let client=ProverClient::from_env().await;
    let started=Instant::now();
    let (mut public_values,report)=client.execute(ELF,stdin.clone()).await.expect("execution failed");
    let execute_ms=started.elapsed().as_secs_f64()*1000.0;
    let result_bytes=public_values.read::<Vec<u8>>();
    let result=BenchResult::decode(&result_bytes).expect("invalid benchmark result");
    println!("mode={mode_name}");
    println!("input_bytes={}",input.len());
    println!("execute_ms={execute_ms:.3}");
    println!("instructions={}",report.total_instruction_count());
    println!("status={:?}",result.status);
    println!("output_bytes={}",result.output_len);
    println!("checksum=0x{:08x}",result.checksum);
    println!("literal_bytes={}",result.literal_bytes);
    println!("match_bytes={}",result.match_bytes);
    println!("tokens={}",result.token_count);
    println!("blocks={}",result.blocks);
    println!("symbols={}",result.symbols);
    println!("extra_bits={}",result.extra_bits);
    println!("table_slots={}",result.table_slots);
    println!("compressed_bits={}",result.compressed_bits);
    println!("runtime_flags=0x{:08x}",result.runtime_flags);
    println!("error_offset={}",result.error_offset);
    println!("detail={}",result.detail);
    if prove {
        let setup_started=Instant::now();
        let pk=client.setup(ELF).await.expect("setup failed");
        let setup_ms=setup_started.elapsed().as_secs_f64()*1000.0;
        let prove_started=Instant::now();
        let proof=client.prove(&pk,stdin).core().await.expect("core proof failed");
        let prove_ms=prove_started.elapsed().as_secs_f64()*1000.0;
        client.verify(&proof,pk.verifying_key(),None).expect("verification failed");
        println!("setup_ms={setup_ms:.3}");
        println!("prove_ms={prove_ms:.3}");
    }
}

fn build_request(mode:&str,input:&[u8],max:u32)->Vec<u8>{
    let no_tokens=[];
    match mode {
        "zlib-ref"=>encode_request(BenchMode::ZlibReference,Codec::Zlib,0,max,32768,0,0,input,&[],&[],&no_tokens),
        "deflate-ref"=>encode_request(BenchMode::DeflateReference,Codec::Deflate,0,max,32768,0,0,input,&[],&[],&no_tokens),
        "brotli-ref"=>encode_request(BenchMode::BrotliReference,Codec::Brotli,0,max,1<<24,0,0,input,&[],&[],&no_tokens),
        "passthrough"=>encode_request(BenchMode::Passthrough,Codec::None,0,max,0,0,0,input,&[],&[],&no_tokens),
        "adler-scalar"=>encode_request(BenchMode::AdlerScalar,Codec::None,FLAG_VERIFY_OUTPUT_LEN,max,0,input.len() as u32,0,input,&[],&[],&no_tokens),
        "adler-batched"=>encode_request(BenchMode::AdlerBatched,Codec::None,FLAG_VERIFY_OUTPUT_LEN,max,0,input.len() as u32,0,input,&[],&[],&no_tokens),
        "zlib-trace"=>encode_request(BenchMode::ZlibTrace,Codec::Zlib,0,max,32768,0,0,input,&[],&[],&no_tokens),
        "lz77-from-zlib"=>{let trace=trace_zlib(input,max as usize).expect("host zlib trace failed");let checksum=trace.adler32.unwrap_or_else(||adler32_batched(&trace.output));encode_request(BenchMode::Lz77Verify,Codec::Zlib,FLAG_VERIFY_OUTPUT_LEN|FLAG_VERIFY_CHECKSUM,max,32768,trace.output.len() as u32,checksum,&[],&trace.output,&trace.literals,&trace.tokens)},
        _=>{eprintln!("unknown mode: {mode}");usage()}
    }
}

fn usage()->!{
    eprintln!("usage: cargo run -p sp1-decompression-script -- <mode> <input> [max_output] [--prove]");
    eprintln!("modes: zlib-ref deflate-ref brotli-ref passthrough adler-scalar adler-batched zlib-trace lz77-from-zlib");
    process::exit(2)
}
