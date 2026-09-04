# Phase 0-2 data sheet

Record each row before any Phase-3 chip design.

| workload | codec | compressed bytes | output bytes | blocks | symbols | table slots | extra bits | literal bytes | match bytes | reference prove ms | best guest prove ms | decompression share |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|

For each workload also capture shard count, peak memory, and per-chip trace area from the prover. Use ablation (pre-decompressed channel) to attribute decompression end-to-end; do not infer that share from instruction count.

## Gate 1 — Amdahl

On the realistic workload, after the best Phase-2 guest implementation, stop if decompression is below roughly 20% of prover wall-clock.

## Gate 2 — analytic floor

Estimate the minimum trace area and memory interactions for each candidate primitive. Continue only for stages whose projected floor is at least roughly 3x better than the best Phase-2 guest stage.

Candidate order:

1. codec-agnostic LZ77 byte-range copy/compare;
2. checksum primitive;
3. prefix-code symbol verification;
4. full DEFLATE only if the narrower primitives fail to capture the measured cost;
5. full Brotli only with a written constraint-count and audit-cost case.
