# Circom-PLONK verifier
To use this verifier, ensure that snarkjs is using poseidon hash.
refer: https://github.com/Janmajayamall/snarkjs

## Use binary verifier
### Requirements
By snarkjs, get PLONK verifier key, proofs, instances.
```
mkdir input
```
### Build
In this folder,
```
cargo build --release
```
### Run
```
./target/release/circom-plonk-verifier -v <vkey.json path> -p <public.json path> --proof <proof.json path>
```
