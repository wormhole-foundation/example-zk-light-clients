use anyhow::Result;
use log::{info, Level};
use near_crypto::{PublicKey, Signature};
use near_primitives::block_header::{Approval, ApprovalInner};
use near_primitives::borsh;
use near_primitives::borsh::BorshDeserialize;
use near_primitives::hash::{hash, CryptoHash};
use near_primitives::types::MerkleHash;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;
use plonky2_field::extension::Extendable;
use serde_json::json;
use std::collections::HashMap;

use crate::prove_crypto::{
    ed25519_proof_reuse_circuit, get_ed25519_targets, prove_sub_hashes_u32, sha256_proof_u32,
};
use crate::recursion::recursive_proof;
use crate::types::*;

/// Computes the hash of a block using its components.
///
/// This function computes the hash of a block by combining the hash of its inner parts
/// (`inner_lite` and `inner_rest`) with the previous block hash (`prev_hash`).
///
/// # Arguments
///
/// * `prev_hash` - The hash of the previous block.
/// * `inner_lite` - A byte slice representing the lite inner part of the block.
/// * `inner_rest` - A byte slice representing the rest of the inner part of the block.
///
/// # Returns
///
/// Returns the computed hash of the block.
pub fn compute_hash(prev_hash: CryptoHash, inner_lite: &[u8], inner_rest: &[u8]) -> CryptoHash {
    let hash_inner = compute_inner_hash(inner_lite, inner_rest);
    combine_hash(&hash_inner, &prev_hash)
}

/// Combines two Merkle hashes into one.
///
/// This function combines two Merkle hashes into a single hash using a borsh serialization.
///
/// # Arguments
///
/// * `hash1` - The first Merkle hash.
/// * `hash2` - The second Merkle hash.
///
/// # Returns
///
/// Returns the combined Merkle hash.
///
pub fn combine_hash(hash1: &MerkleHash, hash2: &MerkleHash) -> MerkleHash {
    CryptoHash::hash_borsh((hash1, hash2))
}

/// Computes the inner hash of a block.
///
/// This function computes the inner hash of a block by hashing its lite inner part
/// (`inner_lite`) and the rest of its inner part (`inner_rest`) and combining them.
///
/// # Arguments
///
/// * `inner_lite` - A byte slice representing the lite inner part of the block.
/// * `inner_rest` - A byte slice representing the rest of the inner part of the block.
///
/// # Returns
///
/// Returns the computed inner hash of the block.
pub fn compute_inner_hash(inner_lite: &[u8], inner_rest: &[u8]) -> CryptoHash {
    let hash_lite = hash(inner_lite);
    let hash_rest = hash(inner_rest);
    combine_hash(&hash_lite, &hash_rest)
}

/// Generates a message to be signed by validators.
pub fn generate_signed_message(
    bh_height: u64,
    nb_height: u64,
    nb_prev_hash: CryptoHash,
) -> Vec<u8> {
    Approval::get_data_for_sig(
            &if bh_height + 1 == nb_height {
            // If the next block exists, the validators sign the hash of the previous one
            ApprovalInner::Endorsement(nb_prev_hash)
        } else {
            // If the next block is missed, the validators sign only the missed height
            ApprovalInner::Skip(bh_height)
        },
        nb_height,
    )
}

/// Proves the header hash for a given header data in u32 format.
///
/// This function generates proofs for the header hash bits using SHA-256 for the provided
/// header data.
///
/// # Arguments
///
/// * `header_hash` - A byte slice representing the header hash.
/// * `header_data` - The header data containing inner_lite, inner_rest, and prev_hash.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with bits public inputs.
///
pub fn prove_header_hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    header_hash: &[u8],
    bp_hash: &[u8],
    header_data: HeaderData,
    timing_tree: &mut TimingTree,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // proof for hash inner_lite
    let hash_lite = hash(&header_data.inner_lite);
    let hash_lite_bytes = borsh::to_vec(&hash_lite)?;
    let (d1, p1) = timed!(
        timing_tree,
        "prove inner_lite hash",
        sha256_proof_u32::<F, C, D>(&header_data.inner_lite, &hash_lite_bytes)?
    );
    // proof for hash inner_rest
    let hash_rest = hash(&header_data.inner_rest);
    let hash_rest_bytes = borsh::to_vec(&hash_rest)?;
    let (d2, p2) = timed!(
        timing_tree,
        "prove inner_rest hash",
        sha256_proof_u32::<F, C, D>(&header_data.inner_rest, &hash_rest_bytes)?
    );
    // verify proofs fot inner_lite & inner_rest
    // concatenate them if both are valid
    // set hashes for inner_lite & inner_rest as PIs
    let (d3, p3) = timed!(
        timing_tree,
        "verify proofs fot inner_lite & inner_rest, set hashes as PIs",
        prove_sub_hashes_u32::<F, C, D>(
            true,
            true,
            &p1.public_inputs,
            &p2.public_inputs,
            None,
            (&d1.common, &d1.verifier_only, &p1),
            Some((&d2.common, &d2.verifier_only, &p2)),
        )?
    );
    // proof for concatenation of inner_hash & prev_hash
    let pis_hash_2: Vec<F> = header_data
        .prev_hash
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    let (d4, p4) = timed!(
        timing_tree,
        "prove concatenation of inner_hash & prev_hash",
        prove_sub_hashes_u32::<F, C, D>(
            true,
            false,
            &p3.public_inputs,
            &pis_hash_2,
            Some(header_hash),
            (&d3.common, &d3.verifier_only, &p3),
            None,
        )?
    );
    d4.verify(p4.clone())?;
    // recursion to set hash (length is 8) & bp hash (length is 32) as PIs
    let bp: Vec<F> = bp_hash.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let (d5, p5) = timed!(
        timing_tree,
        "prove recursion  to set hash (length is 8) & bp hash (length is 32) as PIs",
        recursive_proof::<F, C, C, D>(
            (&d4.common, &d4.verifier_only, &p4.clone()),
            None,
            Some(&[p4.public_inputs, bp].concat())
        )?
    );
    Ok((d5, p5))
}

/// Proves the correctness of a hash of validators list.
///
/// This function generates a proof to verify the correctness of a block producer hash (`bp_hash`)
/// based on the provided validators.
///
/// # Arguments
///
/// * `bp_hash` - A byte slice representing the block producer hash to be verified.
/// * `validators` - A vector containing byte slices representing the validators' data.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs in format of u32
/// if the operation succeeds.
pub fn prove_bp_hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    bp_hash: &[u8],
    validators: Vec<Vec<u8>>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let validators_len = u32::try_from(validators.len())?;
    let mut final_bytes: Vec<u8> = vec![];
    final_bytes.append(&mut validators_len.to_le_bytes().to_vec());
    let count = validators
        .iter()
        .map(|value| final_bytes.append(&mut (*value).to_vec()))
        .count();
    assert_eq!(count, validators.len());
    let (data, proof) = sha256_proof_u32::<F, C, D>(&final_bytes, bp_hash)?;
    Ok((data, proof))
}

/// Prove signatures (approvals) from the next block by public keys (validators) from the previous epoch block.
/// for the message (hash or height depends on the existance of the next block) from the current block.
pub fn prove_approvals<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    approvals: Vec<Vec<u8>>,
    validators: Vec<Vec<u8>>,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    Vec<u8>,
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut ed25519_circuits: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> = HashMap::new();
    let mut agg_data_proof: Vec<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> = vec![];
    let mut valid_keys: Vec<u8> = vec![];
    let stakes_sum: u128 = validators
        .iter()
        .map(|item| {
            let item_len = item.len();
            let item_bytes = &item[item_len - STAKE_BYTES..];
            let mut item_const = [0u8; 16];
            item_const[..16].copy_from_slice(item_bytes);
            u128::from_le_bytes(item_const)
        })
        .sum();
    let mut valid_stakes_sum = 0;
    for (pos, approval) in approvals.iter().enumerate() {
        // signature length (64 bytes) plus Option type (byte), plus signature type (byte)
        if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
            let validator_len = validators[pos].len();
            let sig = Signature::try_from_slice(&approval[1..])?;
            let pk = PublicKey::try_from_slice(
                &validators[pos][(validator_len - STAKE_BYTES - PK_BYTES - TYPE_BYTE)
                    ..(validator_len - STAKE_BYTES)],
            )?;
            let verify: bool = sig.verify(msg, &pk);
            if verify {
                if (3 * valid_stakes_sum) > (2 * stakes_sum) {
                    break;
                }
                if agg_data_proof.is_empty() {
                    agg_data_proof.push(ed25519_proof_reuse_circuit(
                        msg,
                        &approval[2..],
                        &validators[pos][(validator_len - STAKE_BYTES - PK_BYTES)
                            ..(validator_len - STAKE_BYTES)],
                        &mut ed25519_circuits,
                    )?);
                } else {
                    let (sig_d, sig_p) = ed25519_proof_reuse_circuit(
                        msg,
                        &approval[2..],
                        &validators[pos][(validator_len - STAKE_BYTES - PK_BYTES)
                            ..(validator_len - STAKE_BYTES)],
                        &mut ed25519_circuits,
                    )?;
                    agg_data_proof[0] = recursive_proof::<F, C, C, D>(
                        (
                            &agg_data_proof[0].0.common,
                            &agg_data_proof[0].0.verifier_only,
                            &agg_data_proof[0].1,
                        ),
                        Some((&sig_d.common, &sig_d.verifier_only, &sig_p)),
                        None,
                    )?;
                }
                valid_keys.push(pos as u8);
                valid_keys.append(
                    &mut validators[pos]
                        [(validator_len - STAKE_BYTES - PK_BYTES)..(validator_len - STAKE_BYTES)]
                        .to_vec(),
                );

                let mut stake_vec = [0u8; 16];
                stake_vec[..16].copy_from_slice(&validators[pos][(validator_len - STAKE_BYTES)..]);
                let stake = u128::from_le_bytes(stake_vec);
                valid_stakes_sum += stake;
            }
        }
    }
    let valid_keys_hash = hash(&valid_keys);
    let valid_keys_hash_vec: Vec<F> = valid_keys_hash
        .0
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    let (aggregated_circuit_data, aggregated_proof) = recursive_proof::<F, C, C, D>(
        (
            &agg_data_proof[0].0.common,
            &agg_data_proof[0].0.verifier_only,
            &agg_data_proof[0].1,
        ),
        None,
        Some(&valid_keys_hash_vec),
    )?;
    Ok(((aggregated_circuit_data, aggregated_proof), valid_keys))
}

/// Prove signatures (approvals) using nats client, assume that nats consumers are started.
pub fn prove_approvals_with_client<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    approvals: Vec<Vec<u8>>,
    validators: Vec<Vec<u8>>,
    client: nats::Connection,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    Vec<u8>,
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut signature_circuit_data: Vec<CircuitData<F, C, D>> = Vec::with_capacity(1);
    let mut valid_keys: Vec<u8> = vec![];
    let result_subscriber = client.subscribe("PROCESS_SIGNATURE_RESULT")?;
    let mut main_counter = 0;
    let stakes_sum: u128 = validators
        .iter()
        .map(|item| {
            let item_len = item.len();
            let item_bytes = &item[item_len - STAKE_BYTES..];
            let mut item_const = [0u8; 16];
            item_const[..16].copy_from_slice(item_bytes);
            u128::from_le_bytes(item_const)
        })
        .sum();
    let mut valid_stakes_sum = 0;
    for (pos, approval) in approvals.iter().enumerate() {
        // signature length (64 bytes) plus Option type (byte), plus signature type (byte)
        if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
            let validator_len = validators[pos].len();
            let sig = Signature::try_from_slice(&approval[1..])?;
            let pk = PublicKey::try_from_slice(
                &validators[pos][(validator_len - STAKE_BYTES - PK_BYTES - TYPE_BYTE)
                    ..(validator_len - STAKE_BYTES)],
            )?;
            let verify: bool = sig.verify(msg, &pk);
            if verify {
                if (3 * valid_stakes_sum) > (2 * stakes_sum) {
                    break;
                }
                let input_task = InputTask {
                    message: msg.to_vec(),
                    approval: approval[2..].to_vec(),
                    validator: validators[pos]
                        [(validator_len - STAKE_BYTES - PK_BYTES)..(validator_len - STAKE_BYTES)]
                        .to_vec(),
                    signature_index: pos,
                };
                let input_bytes = serde_json::to_vec(&json!(input_task))?;
                client
                    .publish("PROVE_SIGNATURE", input_bytes)
                    .expect("Error publishing proving task");
                main_counter += 1;
                let mut stake_vec = [0u8; 16];
                stake_vec[..16].copy_from_slice(&validators[pos][(validator_len - STAKE_BYTES)..]);
                let stake = u128::from_le_bytes(stake_vec);
                valid_stakes_sum += stake;
            }
        }
    }
    let msg_len_in_bits = msg.len() * 8;
    let (circuit_data, _) = get_ed25519_targets(msg_len_in_bits).unwrap();
    signature_circuit_data.push(circuit_data);

    let mut agg_data = signature_circuit_data[0].clone();
    let mut agg_proofs = Vec::with_capacity(1);
    let mut aux_counter = 0;
    loop {
        if aux_counter == main_counter {
            break;
        }
        if let Some(message) = result_subscriber.iter().next() {
            if let Ok(payload) = serde_json::from_slice::<OutputTask>(&message.data) {
                info!("Processing signature: {}", payload.signature_index);
                let serialized_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
                    payload.proof,
                    &signature_circuit_data[0].common,
                )?;
                let verifier_only_data =
                    VerifierOnlyCircuitData::from_bytes(payload.verifier_data).unwrap();
                if agg_proofs.is_empty() {
                    agg_proofs.push(serialized_proof);
                    agg_data = CircuitData {
                        prover_only: agg_data.prover_only,
                        verifier_only: verifier_only_data,
                        common: agg_data.common,
                    }
                } else {
                    (agg_data, agg_proofs[0]) = recursive_proof::<F, C, C, D>(
                        (&agg_data.common, &agg_data.verifier_only, &agg_proofs[0]),
                        Some((
                            &signature_circuit_data[0].common,
                            &verifier_only_data,
                            &serialized_proof,
                        )),
                        None,
                    )?;
                }
                let signature_index = payload.signature_index;
                valid_keys.push(signature_index as u8);
                let validator_len = validators[signature_index].len();
                valid_keys.append(
                    &mut validators[signature_index]
                        [(validator_len - STAKE_BYTES - PK_BYTES)..(validator_len - STAKE_BYTES)]
                        .to_vec(),
                );
                aux_counter += 1;
            }
        }
    }
    let valid_keys_hash = hash(&valid_keys);
    let valid_keys_hash_vec: Vec<F> = valid_keys_hash
        .0
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    (agg_data, agg_proofs[0]) = recursive_proof::<F, C, C, D>(
        (&agg_data.common, &agg_data.verifier_only, &agg_proofs[0]),
        None,
        Some(&valid_keys_hash_vec),
    )?;
    Ok(((agg_data, agg_proofs[0].clone()), valid_keys))
}

/// Prove the existence of chosen keys while proving signatures in the validators list.
/// Prove that the list of valid keys gives 2/3 of the total sum of all stakes.
/// Public inputs are a set of valid keys with their indices & 2/3 of the total sum of all stakes.
pub fn prove_valid_keys_stakes_in_valiators_list<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    valid_keys_hash: Vec<u8>,
    valid_keys: Vec<u8>,
    validators: Vec<Vec<u8>>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut all_validators_values: Vec<Vec<F>> = vec![];
    for i in validators.iter() {
        let a: Vec<F> = i.iter().map(|x| F::from_canonical_u8(*x)).collect();
        all_validators_values.push(a);
    }
    let valid_keys_values: Vec<F> = valid_keys
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    let mut all_validators_targets: Vec<Vec<Target>> = vec![];
    let mut valid_keys_targets: Vec<Target> = vec![];
    let mut pw = PartialWitness::new();
    for validator in all_validators_values.iter() {
        let a = builder.add_virtual_targets(validator.len());
        for j in 0..validator.len() {
            pw.set_target(a[j], validator[j]);
        }
        all_validators_targets.push(a);
    }
    for i in 0..valid_keys_values.len() {
        valid_keys_targets.push(builder.add_virtual_target());
        pw.set_target(valid_keys_targets[i], valid_keys_values[i]);
    }
    const STAKE_SUM_LEN: usize = STAKE_BYTES + 1;
    let mut valid_stake_sum: Vec<Target> = [builder.zero(); STAKE_SUM_LEN].to_vec();
    for i in (0..valid_keys_values.len()).step_by(PK_BYTES + 1) {
        let pos = valid_keys_values[i].to_noncanonical_u64() as usize;
        let len = all_validators_targets[pos].len();
        // check key
        for j in 0..PK_BYTES {
            builder.connect(
                all_validators_targets[pos][(len - STAKE_BYTES - PK_BYTES) + j],
                valid_keys_targets[(i + 1) + j],
            );
        }
        // compute sum of valid stakes
        let mut crr = builder.zero();
        for j in 0..STAKE_BYTES {
            let sum = builder.add_many([
                &valid_stake_sum[j],
                &all_validators_targets[pos][(len - STAKE_BYTES) + j],
                &crr,
            ]);
            let bits = builder.split_le(sum, 16);
            let s = builder.le_sum(bits[0..8].iter());
            crr = builder.le_sum(bits[8..16].iter());
            valid_stake_sum[j] = s;
        }
        valid_stake_sum[STAKE_SUM_LEN - 1] = builder.add(valid_stake_sum[STAKE_SUM_LEN - 1], crr);
    }
    // compute sum of all stakes
    let mut stake_sum: Vec<Target> = [builder.zero(); STAKE_SUM_LEN].to_vec();
    for validator in all_validators_targets.iter() {
        let len = validator.len();
        let mut crr = builder.zero();
        for j in 0..STAKE_BYTES {
            let sum = builder.add_many([&stake_sum[j], &validator[(len - STAKE_BYTES) + j], &crr]);
            let bits = builder.split_le(sum, 16);
            let s = builder.le_sum(bits[0..8].iter());
            crr = builder.le_sum(bits[8..16].iter());
            stake_sum[j] = s;
        }
        stake_sum[STAKE_SUM_LEN - 1] = builder.add(stake_sum[STAKE_SUM_LEN - 1], crr);
    }
    // compute (3 * valid_stake_sum)
    let three = builder.constant(F::from_canonical_u8(3));
    let mut three_times_valid_stake_sum: Vec<Target> =
        builder.add_virtual_targets(valid_stake_sum.len());
    let mut crr = builder.zero();
    for i in 0..valid_stake_sum.len() {
        let t = builder.mul_add(valid_stake_sum[i], three, crr);
        let bits = builder.split_le(t, 10);
        three_times_valid_stake_sum[i] = builder.le_sum(bits[0..8].iter());
        crr = builder.le_sum(bits[8..10].iter());
    }
    three_times_valid_stake_sum.push(crr);
    // compute (2 * all_stake_sum)
    let two = builder.two();
    let mut crr = builder.zero();
    for stake in &mut stake_sum {
        let t = builder.mul_add(*stake, two, crr);
        let bits = builder.split_le(t, 9);
        *stake = builder.le_sum(bits[0..8].iter());
        crr = builder.le_sum(bits[8..9].iter());
    }
    stake_sum.push(crr);
    // if all_stake_sum array is bigger and there are non zero elements
    // then valid_stake_sum is not 2/3 of stake2
    let zero = builder.zero();
    for stake in stake_sum.iter().skip(valid_stake_sum.len()) {
        builder.connect(*stake, zero);
    }
    // check if valid_stake_sum_3 >= all_stake_sum
    let mut res: Vec<Target> = builder.add_virtual_targets(three_times_valid_stake_sum.len());
    let mut i = (three_times_valid_stake_sum.len() - 1) as isize;
    let mut prev = (BoolTarget::new_unsafe(zero), zero);
    // stakes are stored in little-endian format
    // start checking from the last element
    while i >= 0 {
        let is_equal = builder.is_equal(
            three_times_valid_stake_sum[i as usize],
            stake_sum[i as usize],
        );
        // check if the difference is negative,
        // then the result is order() - stake2_targets[i]
        // in bytes [0xFF 0xFF 0xFF 0xFE 0xFF 0xFF 0xFF 0xXX]
        let is_positive = {
            let sub = builder.sub(
                three_times_valid_stake_sum[i as usize],
                stake_sum[i as usize],
            );
            let sub_bits = builder.split_le(sub, 64);
            let a1 = builder.constant(F::from_canonical_u8(0xFF));
            let a2 = builder.constant(F::from_canonical_u8(0xFE));
            let mut s = zero;
            for j in (8..sub_bits.len()).step_by(8) {
                let number = builder.le_sum(sub_bits[j..(j + 8)].iter());
                match j {
                    32 => {
                        let q = builder.is_equal(number, a2);
                        s = builder.add(s, q.target);
                    }
                    _ => {
                        let q = builder.is_equal(number, a1);
                        s = builder.add(s, q.target);
                    }
                }
            }
            s
        };
        if (i as usize) == three_times_valid_stake_sum.len() - 1 {
            res[i as usize] = builder.select(
                BoolTarget::new_unsafe(is_positive),
                stake_sum[i as usize],
                three_times_valid_stake_sum[i as usize],
            );
            prev = (is_equal, is_positive);
        } else {
            prev = {
                let q = builder.is_equal(prev.0.target, prev.1);
                let tmp1 = builder.select(q, prev.0.target, is_equal.target);
                let tmp2 = builder.select(q, prev.1, is_positive);
                (BoolTarget::new_unsafe(tmp1), tmp2)
            };
            res[i as usize] = builder.select(
                BoolTarget::new_unsafe(prev.1),
                stake_sum[i as usize],
                three_times_valid_stake_sum[i as usize],
            );
        };
        i -= 1;
    }
    for i in 0..three_times_valid_stake_sum.len() {
        builder.connect(three_times_valid_stake_sum[i], res[i]);
    }
    builder.register_public_inputs(&valid_keys_targets);
    builder.register_public_inputs(&valid_stake_sum);
    let keys_stakes_data = builder.build();
    let keys_stakes_proof = keys_stakes_data.prove(pw)?;
    let (keys_hash_data, keys_hash_proof) =
        sha256_proof_u32::<F, C, D>(&valid_keys, &valid_keys_hash)?;
    let (agg_data, agg_proof) = recursive_proof::<F, C, C, D>(
        (
            &keys_stakes_data.common,
            &keys_stakes_data.verifier_only,
            &keys_stakes_proof,
        ),
        Some((
            &keys_hash_data.common,
            &keys_hash_data.verifier_only,
            &keys_hash_proof,
        )),
        Some(&keys_stakes_proof.public_inputs),
    )?;
    Ok((agg_data, agg_proof))
}

/// Prove the existence of chosen keys while proving signatures in the validators list.
/// Public inputs is a set of valid keys with their indices.
pub fn prove_valid_keys_in_validators_list<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    valid_keys: Vec<u8>,
    validators: Vec<Vec<u8>>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let time = TimingTree::new("prove keys for valid signatures", log::Level::Info);
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut validators_values: Vec<Vec<F>> = vec![];
    for i in validators.iter() {
        let a: Vec<F> = i.iter().map(|x| F::from_canonical_u8(*x)).collect();
        validators_values.push(a);
    }
    let valid_validators_values: Vec<F> = valid_keys
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    let mut validators_targets: Vec<Vec<Target>> = vec![];
    let mut valid_validators_targets: Vec<Target> = vec![];
    let mut pw = PartialWitness::new();
    for validator in validators_values.iter() {
        let a = builder.add_virtual_targets(validator.len());
        for j in 0..validator.len() {
            pw.set_target(a[j], validator[j]);
        }
        validators_targets.push(a);
    }
    for i in 0..valid_validators_values.len() {
        valid_validators_targets.push(builder.add_virtual_target());
        pw.set_target(valid_validators_targets[i], valid_validators_values[i]);
    }
    builder.register_public_inputs(&valid_validators_targets);
    for i in (0..valid_validators_values.len()).step_by(PK_BYTES + 1) {
        let pos = valid_validators_values[i].to_noncanonical_u64() as usize;
        let len = validators_targets[pos].len();
        for j in 0..PK_BYTES {
            builder.connect(
                validators_targets[pos][len - STAKE_BYTES - PK_BYTES + j],
                valid_validators_targets[(i + 1) + j],
            );
        }
    }
    let timing = TimingTree::new("build", Level::Info);
    let data = builder.build();
    timing.print();
    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw)?;
    timing.print();
    time.print();
    Ok((data, proof))
}

/// Prove current block depending on previous block header, next bp hash.
pub fn prove_current_block<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    current_block_header_hash_bytes: &[u8],
    current_block_header_bytes: &[u8],
    msg_to_sign: &[u8],
    approvals_bytes: Vec<Vec<u8>>,
    validators_bytes: Vec<Vec<u8>>,
    client: Option<nats::Connection>,
    (prev_epoch_block_data, prev_epoch_block_proof): (
        &VerifierCircuitData<F, C, D>,
        &ProofWithPublicInputs<F, C, D>,
    ),
    timing_tree: &mut TimingTree,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let (mut agg_data, mut agg_proof): (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>);
    // prove hash for current block
    let (cb_hash_data, cb_hash_proof) = timed!(
        timing_tree,
        "prove hash of current block",
        prove_header_hash::<F, C, D>(
            &current_block_header_hash_bytes,
            &current_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES
                - PK_BYTES
                - PK_BYTES)
                ..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)],
            HeaderData {
                prev_hash: current_block_header_bytes[TYPE_BYTE..(TYPE_BYTE + PK_BYTES)].to_vec(),
                inner_lite: current_block_header_bytes
                    [(TYPE_BYTE + PK_BYTES)..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)]
                    .to_vec(),
                inner_rest: current_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)
                    ..(current_block_header_bytes.len() - TYPE_BYTE - SIG_BYTES)]
                    .to_vec(),
            },
            timing_tree
        )?
    );
    info!(
        "Block hash proof size: {} bytes",
        cb_hash_proof.to_bytes().len()
    );
    (agg_data, agg_proof) = {
        // prove sig-s for current block
        let ((cb_sig_data, cb_sig_proof), valid_keys_23stakes) = match client {
            None => {
                timed!(
                    timing_tree,
                    "prove signatures",
                    prove_approvals::<F, C, D>(
                        msg_to_sign,
                        approvals_bytes,
                        validators_bytes.clone()
                    )?
                )
            }
            Some(client_connection) => {
                timed!(
                    timing_tree,
                    "prove signatures using nats client",
                    prove_approvals_with_client::<F, C, D>(
                        msg_to_sign,
                        approvals_bytes,
                        validators_bytes.clone(),
                        client_connection
                    )?
                )
            }
        };

        info!(
            "Size of proof for aggregated signatures: {} bytes",
            cb_sig_proof.to_bytes().len()
        );
        let valid_keys_hash: Vec<u8> = cb_sig_proof
            .public_inputs
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        // prove keys used to verify valid signatures
        let (cb_keys_23stakes_data, cb_keys_23stakes_proof) = timed!(
            timing_tree,
            "prove keys used to verify valid signatures",
            prove_valid_keys_stakes_in_valiators_list::<F, C, D>(
                valid_keys_hash,
                valid_keys_23stakes.clone(),
                validators_bytes.clone(),
            )?
        );
        info!(
            "Size of proof for aggregated keys: {} bytes",
            cb_keys_23stakes_proof.to_bytes().len()
        );

        let pi: Vec<F> = valid_keys_23stakes
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect();

        timed!(
            timing_tree,
            "aggregate signatures and valid keys proof",
            recursive_proof::<F, C, C, D>(
                (
                    &cb_sig_data.common,
                    &cb_sig_data.verifier_only,
                    &cb_sig_proof,
                ),
                Some((
                    &cb_keys_23stakes_data.common,
                    &cb_keys_23stakes_data.verifier_only,
                    &cb_keys_23stakes_proof,
                )),
                Some(&pi),
            )?
        )
    };

    let next_bp_hash: Vec<u8> = prev_epoch_block_proof.public_inputs[8..]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    // prove next_bp_hash
    let (bp_hash_data, bp_hash_proof) = timed!(
        timing_tree,
        "prove next bp hash",
        prove_bp_hash::<F, C, D>(&next_bp_hash, validators_bytes)?
    );
    info!(
        "Bp_hash proof size: {} bytes",
        bp_hash_proof.to_bytes().len()
    );

    (agg_data, agg_proof) = timed!(
        timing_tree,
        "aggregate next bp hash proof",
        recursive_proof::<F, C, C, D>(
            (&agg_data.common, &agg_data.verifier_only, &agg_proof),
            Some((
                &bp_hash_data.common,
                &bp_hash_data.verifier_only,
                &bp_hash_proof,
            )),
            Some(&bp_hash_proof.public_inputs),
        )?
    );

    (agg_data, agg_proof) = timed!(
        timing_tree,
        "aggregate prev epoch block proof",
        recursive_proof::<F, C, C, D>(
            (&agg_data.common, &agg_data.verifier_only, &agg_proof),
            Some((
                &prev_epoch_block_data.common,
                &prev_epoch_block_data.verifier_only,
                &prev_epoch_block_proof,
            )),
            Some(&prev_epoch_block_proof.public_inputs),
        )?
    );

    let pi = [
        prev_epoch_block_proof.public_inputs[0..8].to_vec().clone(),
        cb_hash_proof.public_inputs[0..8].to_vec().clone(),
    ]
    .concat();
    (agg_data, agg_proof) = timed!(
        timing_tree,
        "aggregate final block proof",
        recursive_proof::<F, C, C, D>(
            (&agg_data.common, &agg_data.verifier_only, &agg_proof),
            Some((
                &cb_hash_data.common,
                &cb_hash_data.verifier_only,
                &cb_hash_proof,
            )),
            Some(&pi),
        )?
    );

    Ok(((cb_hash_data, cb_hash_proof), (agg_data, agg_proof)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{load_block_header, load_validators};
    use anyhow::Result;
    use log::info;
    use near_crypto::{KeyType, SecretKey};
    use near_primitives::borsh::BorshSerialize;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use sha2::Digest;

    #[test]
    fn test_compute_hash_for_block() -> Result<()> {
        let path = "../data/prev_epoch_block_header_small.json".to_string();
        let (block_hash, block_header) = load_block_header(&path)?;
        let computed_block_hash = compute_hash(
            *block_header.prev_hash(),
            &block_header.inner_lite_bytes(),
            &block_header.inner_rest_bytes(),
        );
        assert_eq!(computed_block_hash, block_hash);
        Ok(())
    }

    #[test]
    fn test_combine_hash_of_two_merkle_hashes() -> Result<()> {
        let path = "../data/block_header_small.json".to_string();
        let (_block_hash, block_header) = load_block_header(&path)?;
        let hash_lite = hash(&block_header.inner_lite_bytes());
        let hash_rest = hash(&block_header.inner_rest_bytes());
        let mut hasher = sha2::Sha256::default();
        (hash_lite, hash_rest).serialize(&mut hasher).unwrap();
        let combined_1 = CryptoHash(hasher.finalize().into());
        let combined_2 = combine_hash(&hash_lite, &hash_rest);
        assert_eq!(combined_1, combined_2);
        Ok(())
    }

    #[test]
    fn test_compute_inner_hash_of_block() -> Result<()> {
        let path = "../data/block_header_small.json".to_string();
        let (_block_hash, block_header) = load_block_header(&path)?;
        let hash_lite = hash(&block_header.inner_lite_bytes());
        let hash_rest = hash(&block_header.inner_rest_bytes());
        let mut hasher = sha2::Sha256::default();
        (hash_lite, hash_rest).serialize(&mut hasher).unwrap();
        let combined = CryptoHash(hasher.finalize().into());
        let hash_inner = compute_inner_hash(
            &block_header.inner_lite_bytes(),
            &block_header.inner_rest_bytes(),
        );
        assert_eq!(combined, hash_inner);
        Ok(())
    }

    #[test]
    fn test_generate_signed_message_for_validators() -> Result<()> {
        let path = "../data/block_header_small.json".to_string();
        let (block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let hash = ApprovalInner::Endorsement(block_hash);
        let msg_to_sign_vec = [
            borsh::to_vec(&hash).unwrap().as_ref(),
            next_block_header.height().to_le_bytes().as_ref(),
        ]
        .concat();
        assert_eq!(msg_to_sign, msg_to_sign_vec);
        Ok(())
    }

    #[test]
    fn test_generate_signed_message_with_missed_next_block() -> Result<()> {
        let path = "../data/block_header_small.json".to_string();
        let (block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small_skip.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        // for this test msg_to_sign containes a block_height & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let height = ApprovalInner::Skip(block_header.height());
        let msg_to_sign_vec = [
            borsh::to_vec(&height).unwrap().as_ref(),
            next_block_header.height().to_le_bytes().as_ref(),
        ]
        .concat();
        assert_eq!(msg_to_sign, msg_to_sign_vec);
        Ok(())
    }

    #[test]
    fn test_prove_header_hash_for_given_header_data() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (current_block_hash, current_block_header) = load_block_header(&path)?;
        let current_block_header_bytes = borsh::to_vec(&current_block_header)?;
        let current_block_header_hash_bytes = borsh::to_vec(&current_block_hash)?;

        let mut timing_tree = TimingTree::new("prove hash", Level::Info);

        let (_data, proof) = timed!(
            timing_tree,
            "prove hash of current block",
            prove_header_hash::<F, C, D>(
                &current_block_header_hash_bytes,
                &current_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES
                    - PK_BYTES
                    - PK_BYTES)
                    ..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)],
                HeaderData {
                    prev_hash: current_block_header_bytes[TYPE_BYTE..(TYPE_BYTE + PK_BYTES)]
                        .to_vec(),
                    inner_lite: current_block_header_bytes
                        [(TYPE_BYTE + PK_BYTES)..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)]
                        .to_vec(),
                    inner_rest:
                        current_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)
                            ..(current_block_header_bytes.len() - TYPE_BYTE - SIG_BYTES)]
                            .to_vec(),
                },
                &mut timing_tree
            )?
        );
        info!("Block hash proof size: {} bytes", proof.to_bytes().len());
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_correctness_of_block_producer_hash() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
        let path = "../data/prev_epoch_block_header_small.json".to_string();
        let (_, prev_epoch_block_header) = load_block_header(&path)?;
        let prev_epoch_block_header_bytes = borsh::to_vec(&prev_epoch_block_header)?;

        let bp_hash = prev_epoch_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES
            - PK_BYTES
            - PK_BYTES)
            ..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)]
            .to_vec();

        let mut timing_tree = TimingTree::new("prove bp hash", Level::Info);

        // prove next_bp_hash
        let (_data, proof) = timed!(
            timing_tree,
            "prove next bp hash",
            prove_bp_hash::<F, C, D>(&bp_hash, validators_bytes)?
        );
        info!("Bp_hash proof size: {} bytes", proof.to_bytes().len());
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_approvals_from_next_block_by_public_keys() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (_block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        let approvals_bytes: Vec<Vec<u8>> = next_block_header
            .approvals()
            .iter()
            .map(|approval| borsh::to_vec(approval).unwrap())
            .collect();

        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();

        let ((_data, proof), _valid_keys) =
            prove_approvals::<F, C, D>(&msg_to_sign, approvals_bytes, validators_bytes)?;
        info!(
            "Size of proof for aggregated signatures: {} bytes",
            proof.to_bytes().len()
        );
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_valid_keys_stakes_in_validators_list() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (_block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        let approvals_bytes: Vec<Vec<u8>> = next_block_header
            .approvals()
            .iter()
            .map(|approval| borsh::to_vec(approval).unwrap())
            .collect();
        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();

        // valid keys
        let mut valid_keys: Vec<u8> = vec![];
        for (pos, approval) in approvals_bytes.iter().enumerate() {
            // signature length (64 bytes) plus Option type (byte), plus signature type (byte)
            if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
                let validator_len = validators_bytes[pos].len();
                let sig = Signature::try_from_slice(&approval[1..])?;
                let pk = PublicKey::try_from_slice(
                    &validators_bytes[pos][(validator_len - STAKE_BYTES - PK_BYTES - TYPE_BYTE)
                        ..(validator_len - STAKE_BYTES)],
                )?;
                let verify: bool = sig.verify(&msg_to_sign, &pk);
                if verify {
                    valid_keys.push(pos as u8);
                    valid_keys.append(
                        &mut validators_bytes[pos][(validator_len - STAKE_BYTES - PK_BYTES)
                            ..(validator_len - STAKE_BYTES)]
                            .to_vec(),
                    );
                }
            }
        }
        let valid_keys_hash = hash(&valid_keys).0.to_vec();
        let (_data, proof) = prove_valid_keys_stakes_in_valiators_list::<F, C, D>(
            valid_keys_hash,
            valid_keys,
            validators_bytes,
        )?;
        info!(
            "Size of proof for aggregated keys & stakes: {} bytes",
            proof.to_bytes().len()
        );
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_valid_keys_in_validators_list() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (_block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        let approvals_bytes: Vec<Vec<u8>> = next_block_header
            .approvals()
            .iter()
            .map(|approval| borsh::to_vec(approval).unwrap())
            .collect();
        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();

        // valid keys
        let mut valid_keys: Vec<u8> = vec![];
        for (pos, approval) in approvals_bytes.iter().enumerate() {
            // signature length (64 bytes) plus Option type (byte), plus signature type (byte)
            if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
                let validator_len = validators_bytes[pos].len();
                let sig = Signature::try_from_slice(&approval[1..])?;
                let pk = PublicKey::try_from_slice(
                    &validators_bytes[pos][(validator_len - STAKE_BYTES - PK_BYTES - TYPE_BYTE)
                        ..(validator_len - STAKE_BYTES)],
                )?;
                let verify: bool = sig.verify(&msg_to_sign, &pk);
                if verify {
                    valid_keys.push(pos as u8);
                    valid_keys.append(
                        &mut validators_bytes[pos][(validator_len - STAKE_BYTES - PK_BYTES)
                            ..(validator_len - STAKE_BYTES)]
                            .to_vec(),
                    );
                }
            }
        }
        let (_data, proof) =
            prove_valid_keys_in_validators_list::<F, C, D>(valid_keys, validators_bytes)?;
        info!(
            "Size of proof for aggregated keys: {} bytes",
            proof.to_bytes().len()
        );
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_current_block() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (current_block_hash, current_block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        let path = "../data/prev_epoch_block_header_small.json".to_string();
        let (prev_epoch_block_hash, prev_epoch_block_header) = load_block_header(&path)?;
        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();

        let current_block_header_bytes = borsh::to_vec(&current_block_header)?;
        let current_block_hash_bytes = borsh::to_vec(&current_block_hash)?;
        let prev_epoch_block_header_bytes = borsh::to_vec(&prev_epoch_block_header)?;
        let prev_epoch_block_hash_bytes = borsh::to_vec(&prev_epoch_block_hash)?;

        let approvals_bytes: Vec<Vec<u8>> = next_block_header
            .approvals()
            .iter()
            .map(|approval| borsh::to_vec(approval).unwrap())
            .collect();
        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            current_block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );

        let mut timing_tree = TimingTree::new("prove previous block", Level::Info);

        let (data, proof) = timed!(
            timing_tree,
            "prove hash of previous block",
            prove_header_hash::<F, C, D>(
                &prev_epoch_block_hash_bytes,
                &prev_epoch_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES
                    - PK_BYTES
                    - PK_BYTES)
                    ..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)],
                HeaderData {
                    prev_hash: prev_epoch_block_header_bytes[TYPE_BYTE..(TYPE_BYTE + PK_BYTES)].to_vec(),
                    inner_lite: prev_epoch_block_header_bytes
                        [(TYPE_BYTE + PK_BYTES)..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)]
                        .to_vec(),
                    inner_rest: prev_epoch_block_header_bytes[(TYPE_BYTE
                        + PK_BYTES
                        + INNER_LITE_BYTES)
                        ..(prev_epoch_block_header_bytes.len() - SIG_BYTES - TYPE_BYTE)]
                        .to_vec(),
                },
                &mut timing_tree
            )?
        );

        let mut timing_tree = TimingTree::new("prove current block", Level::Info);

        let (
            (_currentblock_header_data, _currentblock_header_proof),
            (_currentblock_data, currentblock_proof),
        ) = timed!(
            timing_tree,
            "prove current block header",
            crate::prove_block::prove_current_block::<F, C, D>(
                &current_block_hash_bytes,
                &current_block_header_bytes,
                &msg_to_sign,
                approvals_bytes,
                validators_bytes,
                None,
                (
                    &data.verifier_data(),
                    &proof
                ),
                &mut timing_tree
            )?
        );

        info!("Proof size {}", currentblock_proof.to_bytes().len());

        Ok(())
    }

}
