use anyhow::{Ok, Result};
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use log::{info, Level};
use near_bft_finality::prove_bft::bft::prove_block_bft;
use near_bft_finality::prove_bft::block_finality::*;
use near_bft_finality::prove_block_data::signatures::generate_signed_message;
use near_bft_finality::prove_crypto::{
    recursion::recursive_proof,
    sha256::{prove_sub_hashes_u32, sha256_proof_u32},
};
use near_bft_finality::types::*;
use near_bft_finality::utils::{load_block_hash, load_block_header, load_validators};
use near_crypto::{PublicKey, Signature};
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
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_bn128::config::PoseidonBN128GoldilocksConfig;
use plonky2_field::extension::Extendable;
use plonky2_field::types::PrimeField64;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::io::BufWriter;

/// Prove BFT finality of the block. The function may be used for both epoch & randomly selected blocks.
///
/// This function proved BFT finality for certain block(s) using four more blocks to ensure full finality.
///
/// # Arguments
///
/// * `epoch_id_i` - Epoch_id of the current epoch, i.e. Epoch_i.
/// * `epoch_id_i_1` - Epoch_id of Epoch_i-1.
/// * `epoch_id_i_2` - Epoch_id of Epoch_i-2.
/// * `epoch_id_i_3` - Epoch_id of Epoch_i-3.
///
/// # Returns
///
/// Returns an array representing data used to prove block BFT finality:
/// * hashes & blocks for Block_0 & Block_n-1 to prove bp_hash & epoch_id -> Vec<(Vec<u8>, Vec<u8>)>.
///   It is represented in the following form: [Block_0 (Epoch_i-1), Block_n-1 (Epoch_i-2), Block_n-1 (Epoch_i-3) (to prove Block_0 (Epoch_i) & Block_n-1 (Epoch_i-1))].
/// * block data and blocks of those blocks whose BFT is proved -> Vec<(BlockDataForFinality, Vec<u8>)>.
///   It is represented in the following form: [Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i] to prove random Block_i.
///   It is represented in the following form: [Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_0, Block_n-1] to prove Block_0 (Epoch_i) & Block_n-1 (Epoch_i-1).
///
pub fn set_blocks(
    epoch_id_i: String,
    // Block_0
    epoch_id_i_1: String,
    // Block_n-1
    epoch_id_i_2: String,
    // Block_n-1
    epoch_id_i_3: Option<String>,
) -> Result<(
    Vec<(Vec<u8>, Vec<u8>)>,
    Vec<(BlockDataForFinality, Vec<u8>)>,
)> {
    // Block_0, Block_n-1, Block_n-1.
    // Stores (hash, header)
    let mut epoch_blocks: Vec<(Vec<u8>, Vec<u8>)> = vec![];
    // Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i/Block_0, Block_n-1.
    let mut blocks: Vec<(BlockDataForFinality, Vec<u8>)> = vec![];

    // Search for folder by epoch_id_i_1 (it should be stored in contract).
    // Extract Block_0.
    let mut folder = epoch_id_i_1.clone();
    let mut file = "block-0.json".to_string();
    let mut path = format!("../data/epochs/{folder}/{file}");
    let (_, mut block_data) = load_block_header(&path)?;
    // Extract Block_0 hash.
    folder = epoch_id_i_1.clone() + "_STORED";
    path = format!("../data/epochs/{folder}/{file}");
    let mut block_hash = load_block_hash(&path)?;
    epoch_blocks.push((borsh::to_vec(&block_hash)?, borsh::to_vec(&block_data)?));

    // Search for folder by epoch_id_i_2 (it should be stored in contract).
    // Extract Block_n-1.
    folder = epoch_id_i_2.clone();
    file = "block-last.json".to_string();
    path = format!("../data/epochs/{folder}/{file}");
    (_, block_data) = load_block_header(&path)?;
    // Extract Block_n-1 hash.
    folder = epoch_id_i_2.clone() + "_STORED";
    path = format!("../data/epochs/{folder}/{file}");
    block_hash = load_block_hash(&path)?;
    epoch_blocks.push((borsh::to_vec(&block_hash)?, borsh::to_vec(&block_data)?));

    if let Some(epoch_id_i_3) = epoch_id_i_3.clone() {
        // Search for folder by epoch_id_i_3 (it should be stored in contract).
        // Extract Block_n-1.
        folder = epoch_id_i_3.clone();
        file = "block-last.json".to_string();
        path = format!("../data/epochs/{folder}/{file}");
        (_, block_data) = load_block_header(&path)?;
        // Extract Block_n-1 hash.
        folder = epoch_id_i_3.clone() + "_STORED";
        path = format!("../data/epochs/{folder}/{file}");
        block_hash = load_block_hash(&path)?;
        epoch_blocks.push((borsh::to_vec(&block_hash)?, borsh::to_vec(&block_data)?));
    }

    let block_type = match epoch_id_i_3 {
        Some(_) => "block-".to_string(),
        None => "random-".to_string(),
    };

    let mut block_num = 4;
    let mut i = 0;
    folder = epoch_id_i.clone();
    while block_num >= 0 {
        // Search for folder by blocks_hash_i (it should be stored in contract).
        // Extract Block_i.
        file = block_type.clone() + block_num.to_string().as_str() + ".json";
        path = format!("../data/epochs/{folder}/{file}");
        (block_hash, block_data) = load_block_header(&path)?;
        let mut approvals: Option<Vec<Vec<u8>>> = None;
        if i == 0 {
            approvals = Some(
                block_data
                    .approvals()
                    .iter()
                    .map(|approval| borsh::to_vec(approval).unwrap())
                    .collect(),
            );
        }

        let block = BlockDataForFinality {
            hash: block_hash.0.to_vec(),
            height: Some(block_data.height()),
            last_ds_final_hash: Some(block_data.last_ds_final_block().0.to_vec()),
            last_final_hash: Some(block_data.last_final_block().0.to_vec()),
            bp_hash: Some(block_data.next_bp_hash().0.to_vec()),
            epoch_id: Some(block_data.epoch_id().0 .0.to_vec()),
            prev_hash: Some(block_data.prev_hash().0.to_vec()),
            approvals,
        };

        blocks.push((block, borsh::to_vec(&block_data)?));

        block_num -= 1;
        i += 1;
    }

    if let Some(epoch_id_i_3) = epoch_id_i_3.clone() {
        // Search for folder by block_hash_i_n_1 (it should be stored in contract).
        // Extract Block_n-1.
        folder = epoch_id_i_1.clone();
        file = "block-last.json".to_string();
        path = format!("../data/epochs/{folder}/{file}");
        (block_hash, block_data) = load_block_header(&path)?;
        let block = BlockDataForFinality {
            hash: block_hash.0.to_vec(),
            height: None,
            last_ds_final_hash: None,
            last_final_hash: None,
            bp_hash: None,
            epoch_id: Some(block_data.epoch_id().0 .0.to_vec()),
            prev_hash: None,
            approvals: None,
        };
        blocks.push((block, borsh::to_vec(&block_data)?));
    }

    Ok((epoch_blocks, blocks))
}

pub async fn prove_block(
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Cbn128 = PoseidonBN128GoldilocksConfig;

    // Prove random block from Epoch_i.
    //let epoch_id_i = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
    //let epoch_id_i_1 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
    //let epoch_id_i_2 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
    //let (epoch_blocks, blocks) = set_blocks(epoch_id_i.clone(), epoch_id_i_1, epoch_id_i_2, None)?;

    // Prove Block_0 & Block_n-1 from Epoch_i & Epoch_i-1.
    let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t".to_string();
    let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
    let epoch_id_i_2 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
    let epoch_id_i_3 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
    let (epoch_blocks, blocks) = set_blocks(
        epoch_id_i.clone(),
        epoch_id_i_1.clone(),
        epoch_id_i_2.clone(),
        Some(epoch_id_i_3.clone()),
    )?;

    assert!(epoch_blocks.len() > 0);
    assert!(epoch_blocks.len() >= 2);
    assert!(epoch_blocks.len() <= 3);

    assert!(blocks.len() > 0);
    assert!(blocks.len() >= 5);
    assert!(blocks.len() <= 6);

    // Block_0 Epoch_i-1.
    let ep_i1_fb_hash_bytes = epoch_blocks[0].0.clone();
    let ep_i1_fb_header_bytes = epoch_blocks[0].1.clone();

    // Block_n-1 of Epoch_i-2.
    let ep_i2_lb_hash_bytes = epoch_blocks[1].0.clone();
    let ep_i2_lb_header_bytes = epoch_blocks[1].1.clone();

    // Block_n-1 of Epoch_i-3.
    let mut ep_i3_lb_hash_bytes: Option<Vec<u8>> = None;
    let mut ep_i3_lb_header_bytes: Option<Vec<u8>> = None;

    if epoch_blocks.len() == 3 {
        ep_i3_lb_hash_bytes = Some(epoch_blocks[2].0.clone());
        ep_i3_lb_header_bytes = Some(epoch_blocks[2].1.clone());
    }
    // Load list of validators for Epoch_i from RPC.
    let path = format!("../data/epochs/{epoch_id_i}/validators.json");
    let validators = load_validators(&path)?;
    let validators_bytes: Vec<Vec<u8>> = validators
        .iter()
        .map(|value| borsh::to_vec(value).unwrap())
        .collect();

    // Load list of validators for Epoch_i-1 from RPC for Block_n-1.
    let mut validators_n_1_bytes: Option<Vec<Vec<u8>>> = None;
    if epoch_blocks.len() == 3 {
        let path = format!("../data/epochs/{epoch_id_i_1}/validators.json");
        let validators_n_1 = load_validators(&path)?;
        let validators_n_1: Vec<Vec<u8>> = validators_n_1
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
        validators_n_1_bytes = Some(validators_n_1);
    }

    // Prove Block_i.
    let ((bi_data, bi_proof), b_n_1_data_proof) = prove_block_bft::<F, C, D>(
        &ep_i2_lb_header_bytes,
        &ep_i2_lb_hash_bytes,
        &ep_i1_fb_header_bytes,
        &ep_i1_fb_hash_bytes,
        ep_i3_lb_header_bytes,
        ep_i3_lb_hash_bytes,
        blocks,
        Some(validators_bytes),
        validators_n_1_bytes,
        None,
        timing_tree,
    )?;

    info!("Final proof size: {} bytes", bi_proof.to_bytes().len());
    info!("PI len: {} bytes", bi_proof.public_inputs.len());

    // In case of proving Block_0 (Epoch_i) & Block_n-1 (Epoch_i-1), it is needed to store their hashes in contract.
    if let Some((b_n_1_data, b_n_1_proof)) = b_n_1_data_proof {
        info!("Final proof size: {} bytes", b_n_1_proof.to_bytes().len());
        info!("PI len: {} bytes", b_n_1_proof.public_inputs.len());
        // Write Block_n-1.
        let hash_bytes: Vec<u8> = b_n_1_proof.public_inputs[0..32]
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        let final_hash = CryptoHash(hash_bytes.try_into().unwrap());
        info!("Hash: {}", final_hash);
        let folder = epoch_id_i_1.clone() + "_STORED";
        let path = format!("../data/epochs/{folder}/block-last.json");
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &final_hash)?;
        // Write Block_0.
        let hash_bytes: Vec<u8> = bi_proof.public_inputs[0..32]
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        let final_hash = CryptoHash(hash_bytes.try_into().unwrap());
        info!("Hash: {}", final_hash);
        let folder = epoch_id_i.clone() + "_STORED";
        let _ = fs::create_dir_all(format!("../data/epochs/{folder}"));
        let path = format!("../data/epochs/{folder}/block-0.json");
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &final_hash)?;
    }

    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info, debug"));
    let mut timing = TimingTree::new("To prove block", Level::Info);
    prove_block(None, &mut timing).await?;
    timing.print();
    Ok(())
}
