use crate::prove_bft::block_finality::*;
use crate::prove_block_data::signatures::generate_signed_message;
use crate::prove_crypto::{
    recursion::recursive_proof,
    sha256::{prove_sub_hashes_u32, sha256_proof_u32},
};
use crate::types::*;
use anyhow::Result;
use log::{info, Level};
use near_primitives::borsh;
use near_primitives::borsh::BorshDeserialize;
use near_primitives::hash::{hash, CryptoHash};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use serde_json::json;

/// Prove BFT finality of the block. The function may be used for both epoch & randomly selected blocks.
///
/// This function proved BFT finality for certain block(s) using four more blocks to ensure full finality.
///
/// # Arguments
///
/// * `ep2_last_block_bytes` - The header data of Block_n-1(Epochi-2) containing inner_lite, inner_rest, and prev_hash.
/// * `ep2_last_block_hash_bytes` - A byte slice representing the header hash.
/// * `ep1_first_block_bytes` - The header data of Block_0(Epochi-1) containing inner_lite, inner_rest, and prev_hash.
/// * `ep1_first_block_hash_bytes` - A byte slice representing the header hash.
/// * `ep3_last_block_bytes` - The header data of Block_n-1(Epochi-3) containing inner_lite, inner_rest, and prev_hash.
/// * `ep3_last_block_hash_bytes` - A byte slice representing the header hash.
/// * `blocks` - A set of blocks udes to prove BFT finality.
///              It is in the following form: [Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i], when proving randomly secected blocks.
///              It is in the following form: [Block_4, Block_3, Block_2, Block_1, Block_0, Block_n-1], when proving epoch blocks.
/// * `validators` - A list of validators that contains public keys & stakes for Epochi.
/// * `validators_n_1` - A list of validators that contains public keys & stakes for Epochi-1.
///
/// # Returns
///
/// Returns a result containing:
/// * one proof when proving ramdomly selected block.
/// * two proofs when proving epoch blocks Block_0 & Block_n-1.
///
pub fn prove_block_bft<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    // Block_n-1(Epochi-2) from RPC.
    ep2_last_block_bytes: &[u8],
    // Extracted from contract.
    ep2_last_block_hash_bytes: &[u8],
    // Block_0(Epochi-1) from RPC.
    ep1_first_block_bytes: &[u8],
    // Extracted from contract.
    ep1_first_block_hash_bytes: &[u8],
    // Block_n-1(Epochi-3) from RPC. To prove Block_n-1 when proving epoch blocks.
    ep3_last_block_bytes: Option<Vec<u8>>,
    // Extracted from contract.
    ep3_last_block_hash_bytes: Option<Vec<u8>>,
    // Blocks_i...i+4 representing some block data used to prove block finality & block itself in bytes.
    blocks: Vec<(BlockDataForFinality, Vec<u8>)>,
    validators: Option<Vec<Vec<u8>>>,
    // List of validators for Block_n-1 (when proving epoch blocks).
    validators_n_1: Option<Vec<Vec<u8>>>,
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    Option<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>,
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // Prove Block_n-1(Epochi-2).
    let (ep2_lb_data, ep2_lb_proof) = prove_block_header::<F, C, D>(
        ep2_last_block_hash_bytes,
        ep2_last_block_bytes,
        None,
        None,
        None,
        None,
        timing_tree,
    )?;
    // Prove Block_0(Epochi-1).
    let (ep1_fb_data, ep1_fb_proof) = prove_block_header::<F, C, D>(
        ep1_first_block_hash_bytes,
        ep1_first_block_bytes,
        None,
        None,
        None,
        Some(
            ep1_first_block_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES - PK_BYTES)
                ..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)]
                .to_vec(),
        ),
        timing_tree,
    )?;
    assert!(blocks.len() > 0);
    // Prove Block_i+4.
    let (b4_data, b4_proof) = prove_block_header::<F, C, D>(
        &blocks[0].0.hash,
        &blocks[0].1,
        None,
        blocks[0].0.last_ds_final_hash.clone(),
        blocks[0].0.last_final_hash.clone(),
        None,
        timing_tree,
    )?;
    // Prove Block_i+3. Doomslag finality.
    let nb_prev_hash: [u8; 32] = blocks[0]
        .0
        .prev_hash
        .clone()
        .expect("No prev_hash for Block3.")
        .try_into()
        .unwrap();
    let nb_prev_hash = CryptoHash(nb_prev_hash);
    let msg_to_sign = generate_signed_message(
        blocks[1].0.height.clone().expect("No height for Block4."),
        blocks[0].0.height.clone().expect("No height for Block3."),
        nb_prev_hash,
    );
    let (b3_data, b3_proof) = prove_block_finality::<F, C, D>(
        &blocks[1].0.hash,
        &blocks[1].1,
        Some(
            blocks[1]
                .0
                .prev_hash
                .clone()
                .expect("No prev_hash for Block_i+3."),
        ),
        Some(
            blocks[1]
                .0
                .last_ds_final_hash
                .clone()
                .expect("No ds_hash for Block_i+3."),
        ),
        Some(
            blocks[1]
                .0
                .last_final_hash
                .clone()
                .expect("No bft_hash for Block_i+3."),
        ),
        Some(
            blocks[1]
                .0
                .epoch_id
                .clone()
                .expect("No epoch_id for Block_i+3."),
        ),
        Some(msg_to_sign),
        blocks[0].0.approvals.clone(),
        // To prove signatures, keys & stakes, bp_hash.
        validators.clone(),
        [
            (
                ep2_lb_data.common.clone(),
                ep2_lb_data.verifier_only.clone(),
                ep2_lb_proof.clone(),
            ),
            (
                ep1_fb_data.common.clone(),
                ep1_fb_data.verifier_only.clone(),
                ep1_fb_proof.clone(),
            ),
            (
                b4_data.common.clone(),
                b4_data.verifier_only.clone(),
                b4_proof.clone(),
            ),
        ]
        .to_vec(),
        client.clone(),
        timing_tree,
    )?;
    // Prove Block_i+2. BFT finality without signatures.
    let (b2_data, b2_proof) = prove_block_finality::<F, C, D>(
        &blocks[2].0.hash,
        &blocks[2].1,
        Some(
            blocks[2]
                .0
                .prev_hash
                .clone()
                .expect("No prev_hash for Block_i+2."),
        ),
        Some(
            blocks[2]
                .0
                .last_ds_final_hash
                .clone()
                .expect("No ds_hash for Block_i+2."),
        ),
        Some(
            blocks[2]
                .0
                .last_final_hash
                .clone()
                .expect("No bft_hash for Block_i_2."),
        ),
        Some(
            blocks[2]
                .0
                .epoch_id
                .clone()
                .expect("No epoch_id for Block_i+2."),
        ),
        None,
        None,
        // To prove bp_hash.
        validators.clone(),
        [
            (
                ep2_lb_data.common.clone(),
                ep2_lb_data.verifier_only.clone(),
                ep2_lb_proof.clone(),
            ),
            (
                ep1_fb_data.common.clone(),
                ep1_fb_data.verifier_only.clone(),
                ep1_fb_proof.clone(),
            ),
            (
                b3_data.common.clone(),
                b3_data.verifier_only.clone(),
                b3_proof.clone(),
            ),
            (
                b4_data.common.clone(),
                b4_data.verifier_only.clone(),
                b4_proof.clone(),
            ),
        ]
        .to_vec(),
        client.clone(),
        timing_tree,
    )?;
    // Prove Block_i+1. BFT finality without signatures.
    let (b1_data, b1_proof) = prove_block_finality::<F, C, D>(
        &blocks[3].0.hash,
        &blocks[3].1,
        Some(
            blocks[3]
                .0
                .prev_hash
                .clone()
                .expect("No prev_hash for Block_i+1."),
        ),
        Some(
            blocks[3]
                .0
                .last_ds_final_hash
                .clone()
                .expect("No ds_hash for Block_i+1."),
        ),
        Some(
            blocks[3]
                .0
                .last_final_hash
                .clone()
                .expect("No bft_hash for Block_i+1."),
        ),
        Some(
            blocks[3]
                .0
                .epoch_id
                .clone()
                .expect("No epoch_id for Block_i+1."),
        ),
        None,
        None,
        // To prove bp_hash.
        validators.clone(),
        [
            (
                ep2_lb_data.common.clone(),
                ep2_lb_data.verifier_only.clone(),
                ep2_lb_proof.clone(),
            ),
            (
                ep1_fb_data.common.clone(),
                ep1_fb_data.verifier_only.clone(),
                ep1_fb_proof.clone(),
            ),
            (
                b2_data.common.clone(),
                b2_data.verifier_only.clone(),
                b2_proof.clone(),
            ),
            (
                b3_data.common.clone(),
                b3_data.verifier_only.clone(),
                b3_proof.clone(),
            ),
        ]
        .to_vec(),
        client.clone(),
        timing_tree,
    )?;
    let ((b_i_0_data, b_i_0_proof), b_n_1_data_proof) = match blocks.len() {
        // Prove ramdomly selected block.
        5 => {
            // Prove Block_i. BFT finality without signatures.
            let (bi_data, bi_proof) = prove_block_finality::<F, C, D>(
                &blocks[4].0.hash,
                &blocks[4].1,
                None,
                None,
                None,
                Some(
                    blocks[4]
                        .0
                        .epoch_id
                        .clone()
                        .expect("No epoch_id for Block_i."),
                ),
                None,
                None,
                // To prove bp_hash.
                validators.clone(),
                [
                    (
                        ep2_lb_data.common.clone(),
                        ep2_lb_data.verifier_only.clone(),
                        ep2_lb_proof.clone(),
                    ),
                    (
                        ep1_fb_data.common.clone(),
                        ep1_fb_data.verifier_only.clone(),
                        ep1_fb_proof.clone(),
                    ),
                    (
                        b1_data.common.clone(),
                        b1_data.verifier_only.clone(),
                        b1_proof.clone(),
                    ),
                    (
                        b2_data.common.clone(),
                        b2_data.verifier_only.clone(),
                        b2_proof.clone(),
                    ),
                ]
                .to_vec(),
                client.clone(),
                timing_tree,
            )?;
            ((bi_data, bi_proof), None)
        }
        // Prove epoch blocks.
        6 => {
            // TODO: Check: list of validators should differ.
            // Prove Block_0. BFT finality without signatures.
            let (b0_data, b0_proof) = prove_block_finality::<F, C, D>(
                &blocks[4].0.hash,
                &blocks[4].1,
                Some(
                    blocks[4]
                        .0
                        .prev_hash
                        .clone()
                        .expect("No prev_hash for Block_n-1."),
                ),
                Some(
                    blocks[4]
                        .0
                        .last_ds_final_hash
                        .clone()
                        .expect("No ds_hash for Block_0."),
                ),
                None,
                Some(
                    blocks[4]
                        .0
                        .epoch_id
                        .clone()
                        .expect("No epoch_id for Block_0."),
                ),
                None,
                None,
                // To prove bp_hash.
                validators.clone(),
                [
                    (
                        ep2_lb_data.common.clone(),
                        ep2_lb_data.verifier_only.clone(),
                        ep2_lb_proof.clone(),
                    ),
                    (
                        ep1_fb_data.common.clone(),
                        ep1_fb_data.verifier_only.clone(),
                        ep1_fb_proof.clone(),
                    ),
                    (
                        b1_data.common.clone(),
                        b1_data.verifier_only.clone(),
                        b1_proof.clone(),
                    ),
                    (
                        b2_data.common.clone(),
                        b2_data.verifier_only.clone(),
                        b2_proof.clone(),
                    ),
                ]
                .to_vec(),
                client.clone(),
                timing_tree,
            )?;
            // Prove Block_n-1.
            // Prove its bp_hash blocks.
            let (ep2_lb_data, ep2_lb_proof) = prove_block_header::<F, C, D>(
                ep2_last_block_hash_bytes,
                ep2_last_block_bytes,
                None,
                None,
                None,
                Some(
                    ep2_last_block_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES
                        - PK_BYTES
                        - PK_BYTES)
                        ..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)]
                        .to_vec(),
                ),
                timing_tree,
            )?;
            // Prove its epoch_id blocks.
            let ep3_last_block_hash_bytes = ep3_last_block_hash_bytes.expect(
                "No hash for Block_n-1(Epochi-3) to prove epoch_id of Block_n-1(Epochi-1).",
            );
            let ep3_last_block_bytes = ep3_last_block_bytes.expect(
                "No hash for Block_n-1(Epochi-3) to prove epoch_id of Block_n-1(Epochi-1).",
            );
            let (ep3_lb_data, ep3_lb_proof) = prove_block_header::<F, C, D>(
                &ep3_last_block_hash_bytes,
                &ep3_last_block_bytes,
                None,
                None,
                None,
                None,
                timing_tree,
            )?;
            // Prove Block_n-1. BFT finality without signatures.
            let (b_n_1_data, b_n_1_proof) = prove_block_finality::<F, C, D>(
                &blocks[5].0.hash,
                &blocks[5].1,
                None,
                None,
                None,
                Some(
                    blocks[5]
                        .0
                        .epoch_id
                        .clone()
                        .expect("No epoch_id for Block_n-1."),
                ),
                None,
                None,
                // To prove bp_hash.
                validators_n_1.clone(),
                [
                    (
                        ep3_lb_data.common.clone(),
                        ep3_lb_data.verifier_only.clone(),
                        ep3_lb_proof.clone(),
                    ),
                    (
                        ep2_lb_data.common.clone(),
                        ep2_lb_data.verifier_only.clone(),
                        ep2_lb_proof.clone(),
                    ),
                    (
                        b0_data.common.clone(),
                        b0_data.verifier_only.clone(),
                        b0_proof.clone(),
                    ),
                    (
                        b1_data.common.clone(),
                        b1_data.verifier_only.clone(),
                        b1_proof.clone(),
                    ),
                ]
                .to_vec(),
                client.clone(),
                timing_tree,
            )?;
            ((b0_data, b0_proof), Some((b_n_1_data, b_n_1_proof)))
        }
        _ => {
            panic!("Invalid blocks.len() {}", blocks.len());
        }
    };
    Ok(((b_i_0_data, b_i_0_proof), b_n_1_data_proof))
}
