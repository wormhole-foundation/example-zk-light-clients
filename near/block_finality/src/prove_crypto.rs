use std::collections::HashMap;

use anyhow::Result;
use log::Level;
use near_primitives::{borsh, hash::hash};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::{
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    util::timing::TimingTree,
};
use plonky2_field::extension::Extendable;

use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets, EDDSATargets};
use plonky2_sha256_u32::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use plonky2_sha256_u32::types::CircuitBuilderHash;

use crate::recursion::recursive_proof;
use crate::utils::vec_u32_to_u8;

pub const SHA256_BLOCK: usize = 512;

/// Verifies that two proofs for hashes are valid & aggregates them into one proof.
/// Concatenates hashes into one array, proves that a hash of the concatenation is equal to the third hash.
/// Aggregates two proofs: aggregation of first two hashes & proof of the third one, sets the third hash as public inputs.
/// All proving functions use u32 values.
/// # Arguments
///
/// * `pis_hash_1` - A first hash represented as an array of field elements as u32.
/// * `pis_hash_2` - A second hash represented as an array of field elements as u32.
/// * `final_hash` - A hash of concatenation of hashes as u8.
/// * `(hash_common_1, hash_verifier_1, hash_proof_1)` - A proof for the first hash.
/// * `hash_data_proof_2` - A proof for the second hash (optional value).
/// * `set_pis_1` - A flag that indicates whether to set first hash as public inputs in aggregation.
/// * `set_pis_2` - A flag that indicates whether to set second hash as public inputs in aggregation.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with the third hash as public inputs.
pub fn prove_sub_hashes_u32<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    set_pis_1: bool,
    set_pis_2: bool,
    pis_hash_1: &[F],
    pis_hash_2: &[F],
    final_hash: Option<&[u8]>,
    (hash_common_1, hash_verifier_1, hash_proof_1): (
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    ),
    hash_data_proof_2: Option<(
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    )>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut pis: Option<&[F]> = Option::None;
    let mut vec = vec![];
    if set_pis_1 {
        vec.append(&mut pis_hash_1.to_vec());
        pis = Some(vec.as_slice());
    }
    if set_pis_2 {
        vec.append(&mut pis_hash_2.to_vec());
        pis = Some(vec.as_slice());
    }
    let (inner_data, inner_proof) = recursive_proof(
        (&hash_common_1, &hash_verifier_1, &hash_proof_1),
        hash_data_proof_2,
        pis,
    )?;
    // prove hash based on two sub hashes
    let pi: Vec<u32> = inner_proof
        .public_inputs
        .iter()
        .map(|x| x.to_canonical_u64() as u32)
        .collect();
    let mut msg = vec_u32_to_u8(&pi);
    if hash_data_proof_2.is_none() {
        let mut hash: Vec<u8> = pis_hash_2
            .iter()
            .map(|x| x.to_noncanonical_u64() as u8)
            .collect();
        msg.append(&mut hash);
    }

    let final_hash_bytes = match final_hash {
        Some(final_hash) => final_hash.to_vec(),
        _ => borsh::to_vec(&hash(&msg))?,
    };

    let (hash_d, hash_p) = sha256_proof_u32(&msg, &final_hash_bytes)?;
    let (result_d, result_p) = recursive_proof(
        (&inner_data.common, &inner_data.verifier_only, &inner_proof),
        Some((&hash_d.common, &hash_d.verifier_only, &hash_p)),
        Some(&hash_p.public_inputs),
    )?;
    Ok((result_d, result_p))
}

/// Computes a SHA-256 proof with public inputs in format of u32 values for a given message and its hash.
///
/// # Arguments
///
/// * `msg` - A slice of bytes representing the message for which the proof is to be computed.
/// * `hash` - A slice of bytes representing the hash of the message.
///
/// # Returns
///
/// Returns a tuple containing the computed circuit data(proving schema) and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with public inputs in u32 limbs.
///
/// # Panics
///
/// This function panics if the proof generation fails.
///
/// # Examples
///
/// ```rust
///
/// use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
/// use block_finality::prove_crypto::sha256_proof_u32;
///
/// const D: usize = 2;
/// type C = PoseidonGoldilocksConfig;
/// type F = <C as GenericConfig<D>>::F;
///
/// // Define a message and its corresponding hash
///
/// let message = "60";
/// let hash = "8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3";
/// let input = hex::decode(message).unwrap();
/// let output = hex::decode(hash).unwrap();
///
/// // Compute SHA-256 proof
/// let (circuit_data, proof) = sha256_proof_u32::<F, C, D>(&input, &output).expect("Error proving sha256 hash");
/// ```
pub fn sha256_proof_u32<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    hash: &[u8],
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let block_num = (len_in_bits + 64 + 512) / 512;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let hash_target = builder.add_virtual_hash_input_target(block_num, SHA256_BLOCK);
    let hash_output = builder.hash_sha256(&hash_target);
    for i in 0..hash_output.limbs.len() {
        builder.register_public_input(hash_output.limbs[i].0);
    }
    let data = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_sha256_input_target(&hash_target, msg);
    pw.set_sha256_output_target(&hash_output, hash);
    let proof = data.prove(pw).unwrap();
    Ok((data, proof))
}

pub fn get_ed25519_circuit_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg_len_in_bits: usize,
    cached_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> (CircuitData<F, C, D>, EDDSATargets) {
    match cached_circuits.get(&msg_len_in_bits) {
        Some(cache) => cache.clone(),
        None => {
            let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
            let targets = ed25519_circuit(&mut builder, msg_len_in_bits);

            let timing = TimingTree::new("build", Level::Info);
            let circuit_data = builder.build::<C>();
            timing.print();

            cached_circuits.insert(msg_len_in_bits, (circuit_data.clone(), targets.clone()));

            (circuit_data, targets)
        }
    }
}

/// Creating ED25519 proof reusing proving schema and targets
pub fn ed25519_proof_reuse_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    ed25519_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let (circuit_data, targets): (CircuitData<F, C, D>, EDDSATargets) =
        get_ed25519_circuit_targets(len_in_bits, ed25519_circuits);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &targets);
    let timing = TimingTree::new("prove", Level::Info);
    let proof = circuit_data.prove(pw)?;
    timing.print();
    Ok((circuit_data, proof))
}

/// Computes an Ed25519 proof for a given message, signature, and public key.
///
/// # Arguments
///
/// * `msg` - A slice of bytes representing the message for which the proof is to be computed.
/// * `sigv` - A slice of bytes representing the Ed25519 signature.
/// * `pkv` - A slice of bytes representing the Ed25519 public key.
/// * `circuit_data` - A tuple containing the existing proving schema and targets.
///
/// # Returns
///
/// Returns a result containing the computed Ed25519 proof with public inputs.
pub fn ed25519_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    circuit_data: (CircuitData<F, C, D>, EDDSATargets),
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &circuit_data.1);
    let timing = TimingTree::new("Prove signature", Level::Info);
    let proof = circuit_data.0.prove(pw)?;
    timing.print();
    Ok(proof)
}

/// Computes EDD5519 targets and proving schema depending on specific message length in bits.
pub fn get_ed25519_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg_len_in_bits: usize,
) -> anyhow::Result<(CircuitData<F, C, D>, EDDSATargets)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = ed25519_circuit(&mut builder, msg_len_in_bits);
    let circuit_data = builder.build::<C>();
    Ok((circuit_data, targets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode_hex;
    use plonky2::plonk::{circuit_data, config::PoseidonGoldilocksConfig};
    use plonky2_field::types::Field;
    use rand::random;

    #[test]
    fn test_prove_sub_hashes_u32_aggregation_correctness() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN: usize = 1000;
        let msg1: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let hash1 = hash(&msg1);
        let msg2: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let hash2 = hash(&msg2);
        let msg3 = [hash1.0, hash2.0].concat();
        let hash3 = hash(&msg3);

        let (d1, p1) = sha256_proof_u32::<F, C, D>(&msg1, &hash1.0)?;
        d1.verify(p1.clone())?;
        let (d2, p2) = sha256_proof_u32::<F, C, D>(&msg2, &hash2.0)?;
        d2.verify(p2.clone())?;
        let (d3, p3) = sha256_proof_u32::<F, C, D>(&msg3, &hash3.0)?;
        d3.verify(p3.clone())?;

        let (_data, _proof) = prove_sub_hashes_u32(
            true,
            true,
            &p1.public_inputs,
            &p2.public_inputs,
            Some(&hash3.0.to_vec()),
            (&d1.common, &d1.verifier_only, &p1),
            Some((&d2.common, &d2.verifier_only, &p2)),
        )?;

        Ok(())
    }

    #[test]
    fn test_sha256_proof_u32_computation_with_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN: usize = 1000;
        let msg: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let hash = hash(&msg);

        let (_data, _proof) = sha256_proof_u32::<F, C, D>(&msg, &hash.0)?;

        Ok(())
    }

    #[test]
    fn test_get_ed25519_circuit_targets_caching() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let msg1 = "test message".to_string();
        let _pk1 = decode_hex(
            &"087CFBF793E35C806B248FA82FC4B4F5A9EC7FFC6088187874AB1ED6519F935A".to_string(),
        )?;
        let _sig1 = decode_hex(&"8158AD38E169B6CD61EE4AB90C041AF459D02C3CDF9D7F4E740CBD623DE34DF808D82AB405D43F4C7998076F63FAA84DCD1DFF5C91426877B51C93B22EDC790A".to_string())?;

        let msg2 = "second one!!".to_string();
        let _pk2 = decode_hex(
            &"87922330C78D15BFEB2669625BA3ED911AD47EFC400B78C4F5E9F6FB5CFB4F2A".to_string(),
        )?;
        let _sig2 = decode_hex(&"AECE7B6A6FB85BE6F484F75D25EB09FC755A9C50500107DFB2478894C9875EE4151ADA9F905F40E09580BF7A4A952024FBAABD4FFAB8C0BC30B8FEAC300D7901".to_string())?;

        let msg3 = "third one".to_string();
        let _sig3 = decode_hex(&"103C8257859C43C75E28C55361C08B61D1C4BDA199FB5943D447F0903F5F1FF780FC77B8D0EAB80802E14A9BF7983C88175F0CCA6D6E9F3E47419A7A34B4710F".to_string())?;

        assert_eq!(msg1.len(), msg2.len());

        let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> =
            HashMap::new();

        let (_data, _targets) = get_ed25519_circuit_targets::<F, C, D>(
            msg1.as_bytes().len(),
            &mut circuit_data_targets,
        );
        assert!(circuit_data_targets.len() == 1);
        let (_data, _targets) = get_ed25519_circuit_targets::<F, C, D>(
            msg2.as_bytes().len(),
            &mut circuit_data_targets,
        );
        assert!(circuit_data_targets.len() == 1);
        let (_data, _targets) = get_ed25519_circuit_targets::<F, C, D>(
            msg3.as_bytes().len(),
            &mut circuit_data_targets,
        );
        assert!(circuit_data_targets.len() == 2);

        Ok(())
    }

    #[test]
    fn test_ed25519_proof_reuse_circuit_reusability() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let msg1 = "test message".to_string();
        let pk1 = decode_hex(
            &"087CFBF793E35C806B248FA82FC4B4F5A9EC7FFC6088187874AB1ED6519F935A".to_string(),
        )?;
        let sig1 = decode_hex(&"8158AD38E169B6CD61EE4AB90C041AF459D02C3CDF9D7F4E740CBD623DE34DF808D82AB405D43F4C7998076F63FAA84DCD1DFF5C91426877B51C93B22EDC790A".to_string())?;

        let msg2 = "second one!!".to_string();
        let pk2 = decode_hex(
            &"87922330C78D15BFEB2669625BA3ED911AD47EFC400B78C4F5E9F6FB5CFB4F2A".to_string(),
        )?;
        let sig2 = decode_hex(&"AECE7B6A6FB85BE6F484F75D25EB09FC755A9C50500107DFB2478894C9875EE4151ADA9F905F40E09580BF7A4A952024FBAABD4FFAB8C0BC30B8FEAC300D7901".to_string())?;

        let msg3 = "third one".to_string();
        let pk3 = decode_hex(
            &"CA8C33194B4C06E205F0FE54C6D902C458278E60410845DFBBF6E2200304D8CF".to_string(),
        )?;
        let sig3 = decode_hex(&"103C8257859C43C75E28C55361C08B61D1C4BDA199FB5943D447F0903F5F1FF780FC77B8D0EAB80802E14A9BF7983C88175F0CCA6D6E9F3E47419A7A34B4710F".to_string())?;

        assert_eq!(msg1.len(), msg2.len());

        let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> =
            HashMap::new();

        let (d1, p1) = ed25519_proof_reuse_circuit::<F, C, D>(
            msg1.as_bytes(),
            &sig1,
            &pk1,
            &mut circuit_data_targets,
        )?;
        d1.verify(p1)?;
        assert!(circuit_data_targets.len() == 1);
        let (d2, p2) = ed25519_proof_reuse_circuit::<F, C, D>(
            msg2.as_bytes(),
            &sig2,
            &pk2,
            &mut circuit_data_targets,
        )?;
        d2.verify(p2)?;
        assert!(circuit_data_targets.len() == 1);
        let (d3, p3) = ed25519_proof_reuse_circuit::<F, C, D>(
            msg3.as_bytes(),
            &sig3,
            &pk3,
            &mut circuit_data_targets,
        )?;
        assert!(circuit_data_targets.len() == 2);
        d3.verify(p3)
    }

    #[test]
    fn test_ed25519_proof_without_reusing_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let msg = "test message".to_string();
        let pk = decode_hex(
            &"087CFBF793E35C806B248FA82FC4B4F5A9EC7FFC6088187874AB1ED6519F935A".to_string(),
        )?;
        let sig = decode_hex(&"8158AD38E169B6CD61EE4AB90C041AF459D02C3CDF9D7F4E740CBD623DE34DF808D82AB405D43F4C7998076F63FAA84DCD1DFF5C91426877B51C93B22EDC790A".to_string())?;

        let (data, targets) = get_ed25519_targets::<F, C, D>(msg.as_bytes().len() * 8)?;
        let proof = ed25519_proof::<F, C, D>(msg.as_bytes(), &sig, &pk, (data.clone(), targets))?;
        data.verify(proof)
    }
}
