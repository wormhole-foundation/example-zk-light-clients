#![no_main]

use ed25519_compact::*;
use plonky2::plonk::{
    circuit_data::CircuitData,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;
use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;

use block_finality::prove_crypto::{ed25519_proof, ed25519_proof_reuse_circuit};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_vec = data.to_vec();

    let keys = KeyPair::generate();
    let pk1 = keys.pk.to_vec();
    let sig1 = keys.sk.sign(data_vec.clone(), None).to_vec();

    let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> =
        HashMap::new();

    let (d1, p1) =
        ed25519_proof_reuse_circuit::<F, C, D>(&data_vec, &sig1, &pk1, &mut circuit_data_targets)
            .expect("Error generating proof.");
    d1.verify(p1).expect("Proof verification failed.");
    assert!(circuit_data_targets.len() == 1);
});
