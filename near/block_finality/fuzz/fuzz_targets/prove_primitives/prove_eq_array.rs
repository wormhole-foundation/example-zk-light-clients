#![no_main]

use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use block_finality::prove_primitives::prove_eq_array;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let (data, proof) = prove_eq_array::<F, C, D>(data, data).expect("Error generating proof");

    assert!(data.verify(proof).is_ok(), "Proof verification failed");
});
