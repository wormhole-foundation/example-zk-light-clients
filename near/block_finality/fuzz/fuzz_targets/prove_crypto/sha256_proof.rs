#![no_main]

use near_primitives::hash::hash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use libfuzzer_sys::fuzz_target;

use block_finality::prove_crypto::sha256_proof_u32;

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_vec = data.to_vec();

    let hash = hash(&data_vec);

    let (data, proof) =
        sha256_proof_u32::<F, C, D>(&data_vec, &hash.0).expect("Error sha256 proof.");

    assert!(data.verify(proof).is_ok(), "Proof verification failed.");
});