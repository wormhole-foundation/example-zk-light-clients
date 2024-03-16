use aptos_lc::crypto::circuit::chunk_step::ChunkStep;
use aptos_lc::crypto::circuit::hash::Sha3;
use aptos_lc::crypto::circuit::{AptosCircuit, E1, S1, S2};
use aptos_lc::crypto::hash::HashValue;
use aptos_lc::crypto::supernova::ProvingSystem;
use arecibo::supernova::NonUniformCircuit;
use arecibo::traits::{Dual, Engine};
use bellpepper::gadgets::multipack::bytes_to_bits;
use bellpepper_merkle_inclusion::traits::GadgetDigest;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use ff::Field;
use rand::{thread_rng, Rng};
use sha3::digest::Output;
use sha3::Digest;
use std::time::Duration;

// To run these benchmarks, first download `criterion` with `cargo install cargo-criterion`.
// Then `cargo criterion --bench proof`.
// For flamegraphs, run `cargo criterion --bench proof --features flamegraph -- --profile-time <secs>`.
// The results are located in `target/criterion/profile/<name-of-benchmark>`.
cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
          name = proof;
          config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
          targets = bench_proof
    }
  } else {
    criterion_group! {
          name = proof;
          config = Criterion::default().warm_up_time(Duration::from_millis(3000));
          targets = bench_proof
    }
  }
}

criterion_main!(proof);

macro_rules! benchmark_for_chunks {
    ($criterion:expr, $siblings_hash_key_elems:expr, $leaf_hash_elems:expr, $root_hash_elems:expr, $( ($proving_sys_assets:ident, $compressed_snark_asset:ident, $iter_per_chunk:expr) ),*) => {
        $(
            let mut $proving_sys_assets = ProvingSystem::<
                E1,
                S1,
                S2,
                $iter_per_chunk,
            >::new(
                <AptosCircuit<<E1 as Engine>::Scalar, ChunkStep<<E1 as Engine>::Scalar>, $iter_per_chunk>>::new(
                    &$siblings_hash_key_elems,
                ),
                [
                    $leaf_hash_elems.as_slice(),
                    $root_hash_elems.as_slice()
                ]
                .concat()
                .to_vec(),
                vec![<Dual<E1> as Engine>::Scalar::ZERO]
            );

        )*

        // Proving group
        let mut recursive_proving_group = $criterion.benchmark_group("Recursive-Proving");
        recursive_proving_group.sampling_mode(SamplingMode::Auto).sample_size(10);

        $(
            let initial_recursive_snark = $proving_sys_assets.recursive_snark().clone();
            recursive_proving_group.bench_with_input(
                BenchmarkId::new("ChunkIters", $iter_per_chunk / 3),
                &$iter_per_chunk,
                |b, _| b.iter(|| {
                    for step in 0..$proving_sys_assets.circuit().iteration_steps().len() + 1 {
                        let circuit_primary = if step == $proving_sys_assets.circuit().iteration_steps().len() {
                            <AptosCircuit<_, _, $iter_per_chunk> as NonUniformCircuit<E1>>::primary_circuit($proving_sys_assets.circuit(), 1)
                        } else {
                            $proving_sys_assets.circuit().get_iteration_circuit(step)
                        };

                        let res = black_box(initial_recursive_snark.clone()).prove_step(
                            black_box($proving_sys_assets.pp()),
                            &circuit_primary,
                            &<AptosCircuit<_, _, $iter_per_chunk> as NonUniformCircuit<E1>>::secondary_circuit($proving_sys_assets.circuit()),
                        );
                        assert!(res.is_ok());
                    }
                }),
            );

            $proving_sys_assets.recursive_proving();
        )*

        recursive_proving_group.finish();

        // Verifying group
        let mut compressed_proving_group = $criterion.benchmark_group("Compressed-Proving");
        compressed_proving_group.sampling_mode(SamplingMode::Auto).sample_size(10);

        $(
            compressed_proving_group.bench_with_input(
                BenchmarkId::new("ChunkIters", $iter_per_chunk / 3),
                &$iter_per_chunk,
                |b, _| b.iter(|| { black_box(&$proving_sys_assets).compressed_proving() }),
            );
        )*

        compressed_proving_group.finish();

        let mut compressed_verify_group = $criterion.benchmark_group("Compressed-Verify");
        compressed_verify_group.sampling_mode(SamplingMode::Auto).sample_size(10);

        $(
            let $compressed_snark_asset =  $proving_sys_assets.compressed_proving();

            compressed_verify_group.bench_with_input(
                BenchmarkId::new("ChunkIters", $iter_per_chunk / 3),
                &$compressed_snark_asset,
                |b, compressed_snark| b.iter(|| $proving_sys_assets.compressed_verify(black_box(&compressed_snark))),
            );
        )*

        compressed_verify_group.finish();
    }
}

/// Return a random `HashValue` for testing.
fn generate_random_hash_value() -> HashValue {
    let mut rng = thread_rng();
    let mut buf = [0u8; 32];
    rng.fill(&mut buf[..]);

    HashValue::from_slice(buf).unwrap()
}

pub fn hash<D: Digest>(data: &[u8]) -> Output<D> {
    let mut hasher = D::new();
    hasher.update(data);

    hasher.finalize()
}

fn bench_proof(c: &mut Criterion) {
    let leaf_hash = generate_random_hash_value();
    let leaf_key = generate_random_hash_value();

    let siblings: Vec<HashValue> = (0..256).map(|_| generate_random_hash_value()).collect();

    let expected_root_hash = siblings
        .iter()
        .zip(leaf_key.iter_bits().take(siblings.len()))
        .fold(leaf_hash, |acc_hash, (sibling_hash, bit)| {
            if bit {
                HashValue::from_slice(hash::<
                    <Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher,
                >(
                    &[sibling_hash.to_vec(), acc_hash.to_vec()].concat()
                ))
                .unwrap()
            } else {
                HashValue::from_slice(hash::<
                    <Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher,
                >(
                    &[acc_hash.to_vec(), sibling_hash.to_vec()].concat()
                ))
                .unwrap()
            }
        });

    let root_hash_elems: Vec<<E1 as Engine>::Scalar> = From::from(&expected_root_hash);
    let leaf_hash_elems: Vec<<E1 as Engine>::Scalar> = From::from(&leaf_hash);

    let leaf_key = bytes_to_bits(leaf_key.as_ref())
        .iter()
        .take(siblings.len())
        .map(|b| {
            if *b {
                <E1 as Engine>::Scalar::ONE
            } else {
                <E1 as Engine>::Scalar::ZERO
            }
        })
        .collect::<Vec<<E1 as Engine>::Scalar>>();

    let mut siblings_hash_key_elems: Vec<<E1 as Engine>::Scalar> = vec![];
    for (sibling, key) in siblings.iter().zip(leaf_key.into_iter()) {
        siblings_hash_key_elems.push(key);
        let mut sib_elems: Vec<<E1 as Engine>::Scalar> = From::from(sibling);
        siblings_hash_key_elems.append(&mut sib_elems);
    }

    benchmark_for_chunks!(
        c,
        siblings_hash_key_elems,
        leaf_hash_elems,
        root_hash_elems,
        (proving_sys_3, compressed_snark_3, 3),
        (proving_sys_12, compressed_snark_12, 12),
        (proving_sys_24, compressed_snark_24, 24),
        (proving_sys_48, compressed_snark_48, 48),
        (proving_sys_96, compressed_snark_96, 96),
        (proving_sys_192, compressed_snark_192, 192)
    );
}
