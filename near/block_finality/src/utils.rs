use std::{env, fs::File, io::Read, num::ParseIntError, str::FromStr};

use near_crypto::PublicKey;
use near_primitives::{
    block_header::BlockHeader,
    hash::CryptoHash,
    types::{validator_stake::ValidatorStake, AccountId},
    views::BlockHeaderView,
};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::types::{BlockParamString, BlockRequest, BlockResponse, ValidatorsOrderedResponse};

pub fn vec_u32_to_u8(data: &Vec<u32>) -> Vec<u8> {
    let capacity = 32 / 8 * data.len();
    let mut output = Vec::<u8>::with_capacity(capacity);
    for &value in data {
        output.push((value >> 24) as u8);
        output.push((value >> 16) as u8);
        output.push((value >> 8) as u8);
        output.push(value as u8);
    }
    output
}

pub fn vec_u8_to_u32(data: &Vec<u8>) -> Vec<u32> {
    assert_eq!(data.len() % 4, 0);
    let capacity = data.len() / 4 as usize;
    let mut output = Vec::<u32>::with_capacity(capacity);
    for i in (0..data.len()).step_by(4) {
        let value = ((data[i] as u32) << 24)
            | ((data[i + 1] as u32) << 16)
            | ((data[i + 2] as u32) << 8)
            | (data[i + 3] as u32);
        output.push(value);
    }
    output
}

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn get_sha256_hash(msg: &[u8]) -> Result<Vec<u8>, ParseIntError> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    decode_hex(&format!("{:x}", hash))
}

pub fn u8bit_to_u8byte(bits: &[u8]) -> Vec<u8> {
    assert_eq!(bits.len() % 8, 0);
    let len = bits.len() / 8;
    let mut bytes: Vec<u8> = (0..len).map(|_| 0).collect();
    let mut j = 7;
    for i in 0..bits.len() {
        if j < 0 {
            j = 7;
        }
        bytes[i / 8] |= bits[i] << j;
        j -= 1;
    }
    bytes
}

/// Loads a block header from a JSON file.
///
/// # Arguments
///
/// * `path` - A string slice representing the path to the JSON file containing block header data.
///
/// # Returns
///
/// Returns a result containing the block hash and the corresponding `BlockHeader` if the operation succeeds.
pub fn load_block_header(path: &str) -> Result<(CryptoHash, BlockHeader), anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let block_response: BlockHeaderView = serde_json::from_str(&data)?;
    let block_header: BlockHeader = BlockHeader::from(block_response.clone());
    Ok((block_response.hash, block_header))
}

/// Loads a block and its header from an RPC endpoint.
///
/// This asynchronous function sends a request to the Near RPC endpoint to retrieve
/// information about a block identified by its hash.
///
/// # Arguments
///
/// * `hash` - A string slice representing the hash of the block to be loaded.
///
/// # Returns
///
/// Returns a result containing a tuple with the block hash and its header if the operation succeeds.
///
/// # Errors
///
/// Returns an error if there are any issues with the RPC request or response handling.
pub async fn load_block_from_rpc(hash: &str) -> Result<(CryptoHash, BlockHeader), anyhow::Error> {
    let rpc_url = env::var("NEAR_RPC").expect("NEAR_PRC parameter missed");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let block_request = BlockRequest {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: BlockParamString {
            block_id: hash.parse().unwrap(),
        },
    };

    let block_response: BlockResponse = client
        .post(rpc_url)
        .json(&block_request)
        .send()
        .await?
        .json()
        .await?;
    let header = BlockHeader::from(block_response.result.header);

    Ok((*header.hash(), header))
}

/// Loads validators and their stakes from a JSON file.
///
/// This function reads validator data from the specified JSON file located at `path`.
/// The JSON file should contain a list of validators with their account IDs, public keys,
/// and stakes. The function parses this JSON data and constructs a vector of `ValidatorStake`
/// structs representing each validator along with their stake.
///
/// # Arguments
///
/// * `path` - A string slice representing the path to the JSON file containing validator data.
///
/// # Returns
///
/// Returns a result containing a vector of `ValidatorStake` structs if the operation succeeds.
///
/// # Errors
///
/// Returns an error if there are any issues reading or parsing the JSON file.
pub fn load_validators(path: &str) -> Result<Vec<ValidatorStake>, anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let validator_response: ValidatorsOrderedResponse = serde_json::from_str(&data)?;
    let validator_stakes: Vec<ValidatorStake> = validator_response
        .result
        .into_iter()
        .map(|validator| {
            ValidatorStake::new_v1(
                AccountId::from_str(&validator.account_id).unwrap(),
                PublicKey::from_str(&validator.public_key).unwrap(),
                validator.stake.parse().unwrap(),
            )
        })
        .collect();
    Ok(validator_stakes)
}

/// Asynchronously loads validator information from RPC endpoint.
///
/// # Arguments
///
/// * `block_hash` - A string representing the hash of the block for which validator information is requested.
///
/// # Returns
///
/// Returns a `Result` containing a vector of `ValidatorStake` objects representing validator information
/// if the operation is successful.
///
/// # Errors
///
/// This function may return an error if:
///
/// * The RPC call fails.
/// * The response from the RPC server is invalid or cannot be parsed.
/// * Validator data cannot be deserialized into `ValidatorStake` objects.
pub async fn load_validators_from_rpc(
    block_hash: &str,
) -> Result<Vec<ValidatorStake>, anyhow::Error> {
    let rpc_url = env::var("NEAR_RPC").expect("NEAR_PRC parameter missed");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let validators_ordered_request = json!({
        "jsonrpc": "2.0",
        "method": "EXPERIMENTAL_validators_ordered",
        "params": vec![block_hash],
        "id": "dontcare"
    });

    let validators_ordered_response: ValidatorsOrderedResponse = client
        .post(rpc_url)
        .json(&validators_ordered_request)
        .send()
        .await?
        .json()
        .await?;

    let _validators_ordered_json_data =
        serde_json::to_string(&validators_ordered_response).unwrap();

    // -------------- serializing EXPERIMENTAL_validators_ordered into ValidatorStake structure --------------

    let validator_stakes = validators_ordered_response
        .result
        .into_iter()
        .map(|validator| {
            ValidatorStake::new_v1(
                AccountId::from_str(&validator.account_id).unwrap(),
                PublicKey::from_str(&validator.public_key).unwrap(),
                validator.stake.parse().unwrap(),
            )
        })
        .collect();

    Ok(validator_stakes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_vec_u32_to_u8() {
        let data = vec![0x11223344, 0xAABBCCDD];
        assert_eq!(
            vec_u32_to_u8(&data),
            vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn test_vec_u32_to_u8_random() {
	for i in 0..10000 {
	    let data: Vec<u32> = (0..i).map(|_| random::<u32>() as u32).collect();
	    vec_u32_to_u8(&data);
	}
    }

    #[test]
    fn test_vec_u8_to_u32() {
        let data = vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD];
        assert_eq!(vec_u8_to_u32(&data), vec![0x11223344, 0xAABBCCDD]);
    }

    #[test]
    fn test_vec_u8_to_u32_random() {
	let mut i = 0;
        while i < 10000 {
            let data: Vec<u8> = (0..i).map(|_| random::<u8>() as u8).collect();
            vec_u8_to_u32(&data);
	    if i == 0 {
                i = 4;
            }
            else {
                i *= 2;
            }
        }
    }

    #[test]
    fn test_decode_hex() {
        let s = String::from("6d657373616765"); // "message" in hexadecimal
        assert_eq!(
            decode_hex(&s),
            Ok(vec![0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,])
        );
    }

    #[test]
    #[should_panic]
    fn test_decode_hex_odd_length() {
        let s = String::from("6d6573736167653"); // "message" in hexadecimal
        let _ = decode_hex(&s).unwrap();
    }

    #[test]
    fn test_get_sha256_hash() {
        let msg = b"";
        assert_eq!(
            get_sha256_hash(msg),
            Ok(vec![
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ])
        );
    }

    #[test]
    fn test_get_sha256_hash_random() {
	for i in 0..10000 {
	    let data: Vec<u8> = (0..i).map(|_| random::<u8>() as u8).collect();
	    let _ = get_sha256_hash(&data);
	}
    }

    #[test]
    fn test_u8bit_to_u8byte() {
        let bits: Vec<u8> = vec![1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1];
        assert_eq!(u8bit_to_u8byte(&bits), vec![0xB2, 0x6B]);
    }

    #[test]
    fn test_u8bit_to_u8byte_random() {
	let mut i = 0;
	while i < 10000 {
	    let data: Vec<u8> = (0..i).map(|_| random::<u8>() as u8).collect();
	    let _ = u8bit_to_u8byte(&data);
	    if i == 0 {
		i = 8;
	    }
	    else {
		i *= 2;
	    }
	}        
    }

    #[test]
    fn test_load_block_header() -> Result<(), anyhow::Error> {
        let block_data = load_block_header("../data/next_block_header.json");
        assert!(block_data.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_block_from_rpc() -> Result<(), anyhow::Error> {
        env::set_var("NEAR_RPC", "https://rpc.mainnet.near.org");
        let block_data = load_block_from_rpc("RuywEaMPnWXkTuRU6LN376T435MnEvb4oeNo5hhMPED").await;
        assert!(block_data.is_ok());
        Ok(())
    }

    #[test]
    fn test_load_validators() -> Result<(), anyhow::Error> {
        let validators = load_validators("../data/validators_ordered.json");
        assert!(validators.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_validators_from_rpc() -> Result<(), anyhow::Error> {
        env::set_var("NEAR_RPC", "https://rpc.mainnet.near.org");
        let validators =
            load_validators_from_rpc("RuywEaMPnWXkTuRU6LN376T435MnEvb4oeNo5hhMPED").await;
        assert!(validators.is_ok());
        Ok(())
    }
}
