#![no_main]

use block_finality::prove_primitives::two_thirds;
use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // Near stake length
    const LEN: usize = 16;

    let value = if data.len() >= LEN {
        data[0..16].to_vec()
    } else {
        let mut tmp = data.to_vec();
        for _ in data.len()..LEN {
            tmp.push(0);
        }
        tmp
    };

    let _value = u128::from_be_bytes(value.clone().try_into().unwrap());

    // more than 2/3
    let value13 = if data.len() > 0 {
        u128::to_be_bytes((_value / 3) * 2 + data[0] as u128)
    } else {
        u128::to_be_bytes((_value / 3) * 2)
    };

    let (data, proof) = two_thirds::<F, C, D>(&value13, &value).expect("Error genetaring proof");

    assert!(data.verify(proof).is_ok(), "Proof verification failed");
});
