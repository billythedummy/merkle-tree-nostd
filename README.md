# merkle-tree-nostd

Simple `no_std` traits for implementing merkle trees. A weekend project used to explore generics and the newfangled const generics.
# Use

Implement the `Hasher` trait, which is designed to work with [ring](https://crates.io/crates/ring)'s `digest` interface. Example using `ring` in [tests/common.rs](tests/common.rs).

## Features:
- no_std
- `verifier()` creates an `Iterator` that yields the successive hashes required to verify a leaf node. This might be useful in streaming scenarios like verifying the integrity of a file live over network.

## Limitations:
- Only supports data/leaf nodes of powers of 2
- Must specify the total capacity of the entire tree at compile time with the const generic param `N` due to current (Rust 1.51.0) limitations of const generics
- Does not do the additional stuff required to mitigate [second preimage attacks](https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack).

## Design
- Backed by array statically allocated at compile time
- Index of hash nodes in the array is left-to-right breadth-first search order, i.e.
```
   0
 1   2
3 4 5 6
```
