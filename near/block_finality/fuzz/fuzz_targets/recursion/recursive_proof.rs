#![no_main]

use block_finality::{prove_primitives::prove_eq_array, recursion::recursive_proof};
use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let (data, proof) = prove_eq_array::<F, C, D>(data, data).expect("Error generating proof.");
    assert!(
        data.verify(proof.clone()).is_ok(),
        "Proof verification failed."
    );

    let (rec_data, rec_proof) = recursive_proof::<F, C, C, D>(
        (&data.common, &data.verifier_only, &proof),
        None,
        Some(&proof.public_inputs),
    )
    .expect("Error generating proof.");
    assert!(
        rec_data.verify(rec_proof).is_ok(),
        "Proof verification failed."
    );
});
