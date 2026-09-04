//! Instrumented RFC 1950/1951 decoder for measurement only.
//! This is not a consensus replacement for `miniz_oxide`.

use alloc::{vec, vec::Vec};
use core::fmt;
use crate::{adler32::adler32_batched, lz77::Lz77Token, prefix::{canonical_codes, CanonicalCode, PrefixErrorKind}};

const LENGTH_BASE: [u16; 29] = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const LENGTH_EXTRA: [u8; 29] = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const DIST_BASE: [u16; 30] = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const DIST_EXTRA: [u8; 30] = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
const CODELEN_ORDER: [usize; 19] = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SymbolTree { CodeLength = 0, LiteralLength = 1, Distance = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolTrace { pub bit_offset: u32, pub symbol: u16, pub code_len: u8, pub tree: SymbolTree }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTrace {
    pub final_block: bool,
    pub block_type: u8,
    pub litlen_lengths: Vec<u8>,
    pub dist_lengths: Vec<u8>,
    pub symbol_start: u32,
    pub symbol_end: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeflateStats {
    pub blocks: u64,
    pub stored_blocks: u64,
    pub fixed_blocks: u64,
    pub dynamic_blocks: u64,
    pub symbols: u64,
    pub extra_bits: u64,
    pub table_slots: u64,
    pub literal_bytes: u64,
    pub match_bytes: u64,
    pub matches: u64,
    pub max_match_len: u32,
    pub max_distance: u32,
    pub compressed_bits: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeflateTrace {
    pub output: Vec<u8>,
    pub literals: Vec<u8>,
    pub tokens: Vec<Lz77Token>,
    pub symbols: Vec<SymbolTrace>,
    pub blocks: Vec<BlockTrace>,
    pub stats: DeflateStats,
    pub adler32: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeflateErrorKind {
    UnexpectedEof=1, BadZlibHeader=2, PresetDictionaryUnsupported=3, ReservedBlockType=4,
    BadStoredLength=5, CodeLengthTooLarge=6, EmptyCodeSet=7, OversubscribedCodeSet=8,
    MissingEndOfBlock=9, InvalidCodeLengthRepeat=10, InvalidLiteralLengthSymbol=11,
    InvalidDistanceSymbol=12, DistanceExceedsOutput=13, OutputLimitExceeded=14,
    AdlerMismatch=15, TrailingData=16, SizeOverflow=17,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateError { pub kind: DeflateErrorKind, pub bit_offset: u32, pub detail: u32 }
impl DeflateError {
    fn at(kind: DeflateErrorKind, bit: usize, detail: usize) -> Self { Self { kind, bit_offset: sat(bit), detail: sat(detail) } }
}
impl fmt::Display for DeflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "DEFLATE {:?} at bit {} ({})", self.kind, self.bit_offset, self.detail) }
}
#[cfg(feature="std")]
impl std::error::Error for DeflateError {}

pub fn trace_deflate(input: &[u8], max_output: usize) -> Result<DeflateTrace, DeflateError> {
    let (trace, consumed) = trace_inner(input, max_output)?;
    if consumed != input.len() { return Err(DeflateError::at(DeflateErrorKind::TrailingData, trace.stats.compressed_bits as usize, input.len()-consumed)); }
    Ok(trace)
}

pub fn trace_zlib(input: &[u8], max_output: usize) -> Result<DeflateTrace, DeflateError> {
    if input.len() < 6 { return Err(DeflateError::at(DeflateErrorKind::UnexpectedEof, 0, input.len())); }
    let cmf=input[0]; let flg=input[1]; let hdr=(u16::from(cmf)<<8)|u16::from(flg);
    if cmf&0x0f != 8 || cmf>>4 > 7 || hdr%31 != 0 { return Err(DeflateError::at(DeflateErrorKind::BadZlibHeader,0,hdr as usize)); }
    if flg&0x20 != 0 { return Err(DeflateError::at(DeflateErrorKind::PresetDictionaryUnsupported,8,0)); }
    let (mut trace, consumed)=trace_inner(&input[2..], max_output)?;
    let trailer=2usize.checked_add(consumed).ok_or_else(|| DeflateError::at(DeflateErrorKind::SizeOverflow,0,consumed))?;
    if trailer.checked_add(4) != Some(input.len()) { return Err(DeflateError::at(DeflateErrorKind::TrailingData, trace.stats.compressed_bits as usize, input.len().saturating_sub(trailer))); }
    let expected=u32::from_be_bytes([input[trailer],input[trailer+1],input[trailer+2],input[trailer+3]]);
    let actual=adler32_batched(&trace.output);
    if actual != expected { return Err(DeflateError { kind: DeflateErrorKind::AdlerMismatch, bit_offset: sat(trace.stats.compressed_bits as usize), detail: actual }); }
    trace.adler32=Some(actual); Ok(trace)
}

fn trace_inner(input:&[u8], max_output:usize)->Result<(DeflateTrace,usize),DeflateError>{
    let mut r=BitReader::new(input);
    let mut t=DeflateTrace{output:Vec::new(),literals:Vec::new(),tokens:Vec::new(),symbols:Vec::new(),blocks:Vec::new(),stats:DeflateStats::default(),adler32:None};
    loop {
        let final_block=r.read(1)?!=0; let block_type=r.read(2)? as u8; t.stats.blocks+=1;
        let symbol_start=sat(t.symbols.len()); let mut ll=Vec::new(); let mut dd=Vec::new();
        match block_type {
            0=>{t.stats.stored_blocks+=1;r.align();let len=r.u16le()?;let nlen=r.u16le()?;if len != !nlen{return Err(DeflateError::at(DeflateErrorKind::BadStoredLength,r.pos,len as usize));}let bytes=r.bytes(len as usize)?;literal_slice(&mut t,bytes,max_output,r.pos)?;}
            1=>{t.stats.fixed_blocks+=1;(ll,dd)=fixed();t.stats.table_slots+=(ll.len()+dd.len()) as u64;decode_block(&mut r,&mut t,&ll,&dd,max_output)?;}
            2=>{t.stats.dynamic_blocks+=1;(ll,dd)=dynamic(&mut r,&mut t)?;t.stats.table_slots+=(ll.len()+dd.len()) as u64;decode_block(&mut r,&mut t,&ll,&dd,max_output)?;}
            _=>return Err(DeflateError::at(DeflateErrorKind::ReservedBlockType,r.pos.saturating_sub(2),3)),
        }
        t.blocks.push(BlockTrace{final_block,block_type,litlen_lengths:ll,dist_lengths:dd,symbol_start,symbol_end:sat(t.symbols.len())});
        if final_block{break;}
    }
    t.stats.compressed_bits=r.pos as u64; let consumed=(r.pos+7)/8; Ok((t,consumed))
}

fn fixed()->(Vec<u8>,Vec<u8>){let mut ll=vec![0u8;288];ll[0..=143].fill(8);ll[144..=255].fill(9);ll[256..=279].fill(7);ll[280..=287].fill(8);(ll,vec![5u8;32])}

fn dynamic(r:&mut BitReader<'_>,t:&mut DeflateTrace)->Result<(Vec<u8>,Vec<u8>),DeflateError>{
    let hlit=r.read(5)? as usize+257; let hdist=r.read(5)? as usize+1; let hclen=r.read(4)? as usize+4;
    let mut lens=vec![0u8;19]; for &i in &CODELEN_ORDER[..hclen]{lens[i]=r.read(3)? as u8;}
    let cb=Codebook::new(&lens,7,false,r.pos)?; t.stats.table_slots+=19;
    let total=hlit+hdist; let mut all=Vec::with_capacity(total);
    while all.len()<total {
        let (s,start,n)=cb.decode(r)?; symbol(t,start,s,n,SymbolTree::CodeLength);
        match s {
            0..=15=>all.push(s as u8),
            16=>{if all.is_empty(){return Err(DeflateError::at(DeflateErrorKind::InvalidCodeLengthRepeat,start,16));}let n=r.read(2)? as usize+3;t.stats.extra_bits+=2;if all.len()+n>total{return Err(DeflateError::at(DeflateErrorKind::InvalidCodeLengthRepeat,start,n));}let p=*all.last().unwrap();all.resize(all.len()+n,p);}
            17=>{let n=r.read(3)? as usize+3;t.stats.extra_bits+=3;if all.len()+n>total{return Err(DeflateError::at(DeflateErrorKind::InvalidCodeLengthRepeat,start,n));}all.resize(all.len()+n,0);}
            18=>{let n=r.read(7)? as usize+11;t.stats.extra_bits+=7;if all.len()+n>total{return Err(DeflateError::at(DeflateErrorKind::InvalidCodeLengthRepeat,start,n));}all.resize(all.len()+n,0);}
            _=>return Err(DeflateError::at(DeflateErrorKind::InvalidCodeLengthRepeat,start,s as usize)),
        }
    }
    let ll=all[..hlit].to_vec();let dd=all[hlit..].to_vec();
    if ll.get(256).copied().unwrap_or(0)==0{return Err(DeflateError::at(DeflateErrorKind::MissingEndOfBlock,r.pos,256));}
    Codebook::new(&ll,15,false,r.pos)?;Codebook::new(&dd,15,true,r.pos)?;Ok((ll,dd))
}

fn decode_block(r:&mut BitReader<'_>,t:&mut DeflateTrace,ll:&[u8],dd:&[u8],max:usize)->Result<(),DeflateError>{
    let lit=Codebook::new(ll,15,false,r.pos)?;let dist=Codebook::new(dd,15,true,r.pos)?;
    loop {
        let(s,start,n)=lit.decode(r)?;symbol(t,start,s,n,SymbolTree::LiteralLength);
        match s {
            0..=255=>literal(t,s as u8,max,start)?,
            256=>return Ok(()),
            257..=285=>{let i=(s-257) as usize;let eb=LENGTH_EXTRA[i];let len=LENGTH_BASE[i] as u32+r.read(eb)?;t.stats.extra_bits+=eb as u64;
                let(ds,dstart,dn)=dist.decode(r)?;symbol(t,dstart,ds,dn,SymbolTree::Distance);if ds>29{return Err(DeflateError::at(DeflateErrorKind::InvalidDistanceSymbol,dstart,ds as usize));}
                let di=ds as usize;let de=DIST_EXTRA[di];let distance=DIST_BASE[di] as u32+r.read(de)?;t.stats.extra_bits+=de as u64;copy_match(t,len,distance,max,dstart)?;}
            _=>return Err(DeflateError::at(DeflateErrorKind::InvalidLiteralLengthSymbol,start,s as usize)),
        }
    }
}

fn symbol(t:&mut DeflateTrace,start:usize,s:u16,n:u8,tree:SymbolTree){t.symbols.push(SymbolTrace{bit_offset:sat(start),symbol:s,code_len:n,tree});t.stats.symbols+=1;}
fn literal(t:&mut DeflateTrace,b:u8,max:usize,bit:usize)->Result<(),DeflateError>{
    if t.output.len()>=max{return Err(DeflateError::at(DeflateErrorKind::OutputLimitExceeded,bit,t.output.len()));}t.output.push(b);t.literals.push(b);
    let count=t.tokens.len();match t.tokens.last_mut(){Some(x) if x.is_literal()=>x.len=x.len.checked_add(1).ok_or_else(||DeflateError::at(DeflateErrorKind::SizeOverflow,bit,count))?,_=>t.tokens.push(Lz77Token::literal(1))};t.stats.literal_bytes+=1;Ok(())
}
fn literal_slice(t:&mut DeflateTrace,b:&[u8],max:usize,bit:usize)->Result<(),DeflateError>{
    let end=t.output.len().checked_add(b.len()).ok_or_else(||DeflateError::at(DeflateErrorKind::SizeOverflow,bit,b.len()))?;if end>max{return Err(DeflateError::at(DeflateErrorKind::OutputLimitExceeded,bit,end));}
    t.output.extend_from_slice(b);t.literals.extend_from_slice(b);if !b.is_empty(){let n=u32::try_from(b.len()).map_err(|_|DeflateError::at(DeflateErrorKind::SizeOverflow,bit,b.len()))?;match t.tokens.last_mut(){Some(x) if x.is_literal()=>x.len=x.len.checked_add(n).ok_or_else(||DeflateError::at(DeflateErrorKind::SizeOverflow,bit,b.len()))?,_=>t.tokens.push(Lz77Token::literal(n))};t.stats.literal_bytes+=b.len() as u64;}Ok(())
}
fn copy_match(t:&mut DeflateTrace,len:u32,distance:u32,max:usize,bit:usize)->Result<(),DeflateError>{
    let l=len as usize;let d=distance as usize;if d==0||d>t.output.len(){return Err(DeflateError::at(DeflateErrorKind::DistanceExceedsOutput,bit,d));}let end=t.output.len().checked_add(l).ok_or_else(||DeflateError::at(DeflateErrorKind::SizeOverflow,bit,l))?;if end>max{return Err(DeflateError::at(DeflateErrorKind::OutputLimitExceeded,bit,end));}
    for _ in 0..l{let b=t.output[t.output.len()-d];t.output.push(b);}t.tokens.push(Lz77Token::match_copy(len,distance));t.stats.matches+=1;t.stats.match_bytes+=len as u64;t.stats.max_match_len=t.stats.max_match_len.max(len);t.stats.max_distance=t.stats.max_distance.max(distance);Ok(())
}

struct Codebook{entries:Vec<CanonicalCode>,max:u8,empty:bool}
impl Codebook{
    fn new(lens:&[u8],max:u8,allow_empty:bool,bit:usize)->Result<Self,DeflateError>{
        if lens.iter().all(|&x|x==0){if allow_empty{return Ok(Self{entries:vec![CanonicalCode::default();lens.len()],max,empty:true});}return Err(DeflateError::at(DeflateErrorKind::EmptyCodeSet,bit,0));}
        let entries=canonical_codes(lens,max,true).map_err(|e|{let k=match e.kind{PrefixErrorKind::CodeLengthTooLarge=>DeflateErrorKind::CodeLengthTooLarge,PrefixErrorKind::Oversubscribed=>DeflateErrorKind::OversubscribedCodeSet,_=>DeflateErrorKind::EmptyCodeSet};DeflateError::at(k,bit,e.detail as usize)})?;Ok(Self{entries,max,empty:false})
    }
    fn decode(&self,r:&mut BitReader<'_>)->Result<(u16,usize,u8),DeflateError>{let start=r.pos;if self.empty{return Err(DeflateError::at(DeflateErrorKind::EmptyCodeSet,start,0));}for n in 1..=self.max{let bits=r.peek(n)?;for(s,e)in self.entries.iter().enumerate(){if e.len==n&&e.code==bits{r.pos+=n as usize;return Ok((s as u16,start,n));}}}Err(DeflateError::at(DeflateErrorKind::EmptyCodeSet,start,0))}
}

struct BitReader<'a>{input:&'a[u8],pos:usize}
impl<'a>BitReader<'a>{
    fn new(input:&'a[u8])->Self{Self{input,pos:0}}
    fn peek(&self,n:u8)->Result<u32,DeflateError>{if n==0{return Ok(0)}let end=self.pos.checked_add(n as usize).ok_or_else(||DeflateError::at(DeflateErrorKind::SizeOverflow,self.pos,n as usize))?;if end>self.input.len().saturating_mul(8){return Err(DeflateError::at(DeflateErrorKind::UnexpectedEof,self.pos,n as usize));}let mut v=0u32;for i in 0..n as usize{let p=self.pos+i;v|=((self.input[p/8]>>(p%8))&1) as u32<<i;}Ok(v)}
    fn read(&mut self,n:u8)->Result<u32,DeflateError>{let v=self.peek(n)?;self.pos+=n as usize;Ok(v)}
    fn align(&mut self){self.pos=(self.pos+7)&!7}
    fn u16le(&mut self)->Result<u16,DeflateError>{if self.pos%8!=0{self.align()}let b=self.bytes(2)?;Ok(u16::from_le_bytes([b[0],b[1]]))}
    fn bytes(&mut self,n:usize)->Result<&'a[u8],DeflateError>{if self.pos%8!=0{return Err(DeflateError::at(DeflateErrorKind::UnexpectedEof,self.pos,n));}let s=self.pos/8;let e=s.checked_add(n).ok_or_else(||DeflateError::at(DeflateErrorKind::SizeOverflow,self.pos,n))?;if e>self.input.len(){return Err(DeflateError::at(DeflateErrorKind::UnexpectedEof,self.pos,n));}self.pos=e*8;Ok(&self.input[s..e])}
}
fn sat(v:usize)->u32{u32::try_from(v).unwrap_or(u32::MAX)}
