#![no_main]

use ed25519_compact::*;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use libfuzzer_sys::fuzz_target;

use block_finality::prove_crypto::{ed25519_proof, get_ed25519_targets};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_vec = data.to_vec();

    //let keys = KeyPair::generate();
    //let pk = keys.pk.to_vec();

    let pk_bytes = [
        248, 137, 130, 32, 199, 137, 101, 139, 162, 79, 53, 29, 125, 5, 62, 32, 88, 106, 168, 15,
        155, 158, 173, 39, 231, 105, 142, 127, 253, 203, 13, 63,
    ]
    .to_vec();
    let sk_bytes = [
        149, 252, 231, 211, 124, 212, 39, 115, 225, 16, 86, 79, 63, 48, 179, 141, 203, 95, 7, 144,
        198, 235, 65, 177, 228, 77, 143, 238, 212, 110, 208, 152, 248, 137, 130, 32, 199, 137, 101,
        139, 162, 79, 53, 29, 125, 5, 62, 32, 88, 106, 168, 15, 155, 158, 173, 39, 231, 105, 142,
        127, 253, 203, 13, 63,
    ]
    .to_vec();
    let sk = SecretKey::from_slice(&sk_bytes).expect("Error getting secret key.");

    let sig_bytes = sk.sign(data_vec.clone(), None).to_vec();

    let (data, targets) =
        get_ed25519_targets::<F, C, D>(data_vec.len() * 8).expect("Error getting targets.");
    let proof = ed25519_proof::<F, C, D>(&data_vec, &sig_bytes, &pk_bytes, (data.clone(), targets))
        .expect("Error generating proof.");

    assert!(data.verify(proof).is_ok());
});
