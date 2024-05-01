#![no_main]

use block_finality::utils::u8bit_to_u8byte;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let data_vec = data.to_vec();
    if data_vec.len() % 8 == 0 {
        let data_byte = u8bit_to_u8byte(&data_vec);
    }
});
