#![no_main]

use libfuzzer_sys::fuzz_target;
use block_finality::utils::decode_hex;
use hex::*;

fuzz_target!(|data: &[u8]| {
    if data.len() % 2 == 0 {
        let str = hex::encode(data);
        let vec = decode_hex(&str).expect("Error converting hex to dec.");
    }
});
