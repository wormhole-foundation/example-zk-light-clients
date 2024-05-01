#![no_main]

use block_finality::utils::get_sha256_hash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hash = get_sha256_hash(data).expect("Error computing sha256.");
});
