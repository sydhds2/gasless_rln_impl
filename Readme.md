# Gasless RLN implementation

This repository contains a research prototype implementation of a gasless transaction system protected by Rate-Limited Nullifiers (RLN).

RLN enforces a fixed number of transactions per epoch per identity, preventing users from exceeding the allowed limit without revealing their secret and triggering slashing.

Warning!: This code is a research prototype. Do not use it in production.

## Gasless simulation

* Standard simulation
  * `RUST_LOG=debug cargo test test_add_to_mempool -- --no-capture`
* User 
  * `RUST_LOG=debug cargo test test_slashing -- --no-capture`

### Implementation notes

* Implemented:
  * User transaction with user generated RLN proof 
  * Proof verification 
  * Slashing user stake if spamming (e.g. exceeding RLN user limit)
* Not implemented
  * Network
  * Epoch handling
* Mocked
  * Sequencer: simple code that only verifies RLN proof - no block generation
  * Smart contract: implemented as Rust service (Rust tokio task)

## RLN benchmark

* Benchmark proof generation time, proof verification time & serialization time
  * `cargo bench -p rln_proof`

### Benchmark results

The benchmark has been run on the following:
* Laptop: AMD Ryzen 7 5825U - 32Go Ram
* Os: Ubuntu 25.10
* Rust: 1.94.1
* RLN: Groth 16 / Merkle tree depth: 20 / [arkworks](https://github.com/arkworks-rs/algebra) crates version 0.5.0

| Benchmark name               | Result (avg) |
|------------------------------|:------------:|
| compute proof and values     |  342.61 ms   | 
| proof verification           |  2.4754 ms   |
| proof & values serialization |  2.8996 µs   |