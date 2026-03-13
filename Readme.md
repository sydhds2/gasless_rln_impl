# Gasless RLN implementation

This repository contains a research prototype implementation of a gasless transaction system protected by Rate-Limited Nullifiers (RLN).

RLN enforces a fixed number of transactions per epoch per identity, preventing users from exceeding the allowed limit without revealing their secret and triggering slashing.

Warning!: This code is a research prototype. Do not use it in production.

## Run the simulations

* Standard simulation
  * `RUST_LOG=debug cargo test test_add_to_mempool -- --no-capture`
* User 
  * `RUST_LOG=debug cargo test test_slashing -- --no-capture`

## Run the benchmark

* Benchmark proof generation time + serialization time
  * `cargo bench -p rln_proof`