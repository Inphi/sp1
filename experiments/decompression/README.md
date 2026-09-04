# SP1 decompression acceleration experiment

This directory implements the **measurement boundary**, not a production precompile. It is intended to answer the build/no-build question before any decompression chip is added to SP1.

## What is implemented

- Reference guest baselines for zlib/DEFLATE (`miniz_oxide`) and Brotli (`brotli`).
- A zlib/DEFLATE tracer that exposes block tables, prefix-code symbol positions, literal runs, LZ77 matches, extra-bit counts, and Adler-32.
- Codec-agnostic LZ77 witness verification: verify the claimed output against literal runs and `(length, distance)` tokens without re-decoding the entropy stream.
- Canonical prefix-code construction plus arbitrary-bit-offset symbol verification helpers.
- Scalar and batched Adler-32 baselines.
- A 4-byte-aligned explicit wire format so guest input serialization does not become part of the stage comparison.
- An SP1 guest and runner that report execution instructions and optionally core-proof wall-clock.

No zkVM syscall, AIR chip, runtime patch, or patched compression crate is introduced here. Phase 3 should only begin after the Phase 0-2 gates are supported by measurements.

## Run

From this directory:

```bash
cargo run -p sp1-decompression-script -- zlib-ref ./corpus/channel.zlib 33554432
cargo run -p sp1-decompression-script -- zlib-trace ./corpus/channel.zlib 33554432
cargo run -p sp1-decompression-script -- lz77-from-zlib ./corpus/channel.zlib 33554432
cargo run -p sp1-decompression-script -- adler-scalar ./corpus/plain.bin 33554432
cargo run -p sp1-decompression-script -- adler-batched ./corpus/plain.bin 33554432
cargo run -p sp1-decompression-script -- brotli-ref ./corpus/channel.br 33554432
```

Append `--prove` to time a core proof. Use identical hardware, SP1 commit, prover settings, and inputs for every comparison.

## Measurement sequence

1. **Reference decoder:** establish the unmodified guest baseline.
2. **Tracer:** measure block count, symbol count, table slots, extra bits, literal/match split, and checksum work.
3. **LZ77 verify:** isolate the cost of verifying an explicit token witness.
4. **Adler scalar vs batched:** establish the best guest-only checksum baseline.
5. Add optimized guest decode/verify variants before considering any chip.

Do not interpret instruction count as a projected precompile speedup. The decision metrics are prover wall-clock and trace area; instruction count is orientation only.

## Consensus caveat

`deflate::trace_zlib` is an instrumented valid-stream tracer, **not** a behavioral replacement for `miniz_oxide`. Before any accelerated path can replace reference decoding, differential fuzzing must prove parity for valid and malformed streams, including incomplete/oversubscribed code sets, single-distance-code cases, reserved symbols, stored-block NLEN failures, boundary distances, trailing data, and Adler-32 mismatch.
