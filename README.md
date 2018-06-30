# bellman-wasm
This is a work in progress to get bellman to generate a circuit and return it's R1CS as an artifact in wasm.

## Current Status
`src/lib.rs` contains an adaption of bellman's mimc circuit test. Bellman doesn't expose enough public APIs to grab the r1cs without generating a prover. Next step should be forking bellman to change a few methods to public methods to enable this.
