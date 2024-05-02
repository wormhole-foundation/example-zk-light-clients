#![no_main]

use block_finality::utils::vec_u8_to_u32;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let data_vec = data.to_vec();
    if data_vec.len() % 4 == 0 {
        let data_u32 = vec_u8_to_u32(&data_vec);
    }
});
