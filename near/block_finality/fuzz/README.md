### Install fuzz
```
rustup install nightly
```
```
cargo +nightly --version
```
```
cargo install cargo-fuzz
```
### Show fuzz targets   
```
cargo fuzz list
```
### Run targets
Useful for all targets, except tests for ed25519, that should be called with flags.
```
cargo +nightly fuzz run fuzz_target_name
```
