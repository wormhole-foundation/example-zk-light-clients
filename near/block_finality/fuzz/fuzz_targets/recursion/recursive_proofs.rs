#![no_main]

use block_finality::{prove_primitives::prove_eq_array, recursion::recursive_proofs};
use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_proof1 = prove_eq_array::<F, C, D>(data, data).expect("Error generating proof.");
    assert!(
        data_proof1.0.verify(data_proof1.1.clone()).is_ok(),
        "Proof verification failed."
    );

    let data_proof2 = prove_eq_array::<F, C, D>(data, data).expect("Error generating proof.");
    assert!(
        data_proof2.0.verify(data_proof2.1.clone()).is_ok(),
        "Proof verification failed."
    );

    let data_proofs = vec![data_proof1, data_proof2];

    let (rec_data, rec_proof) =
        recursive_proofs::<F, C, D>(&data_proofs, None).expect("Error generating proof.");
    assert!(
        rec_data.verify(rec_proof).is_ok(),
        "Proof verification failed."
    );
});
