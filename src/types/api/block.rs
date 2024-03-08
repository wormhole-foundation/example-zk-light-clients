// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::crypto::hash::HashValue;
use crate::types::api::error::ApiError;
use crate::types::block_info::BlockInfo;
use anyhow::Result;
use getset::{CopyGetters, Getters};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Default, Debug, CopyGetters, Getters, Serialize, Deserialize)]
struct Block {
    pub block_height: String,
    pub block_hash: String,
    pub block_timestamp: String,
    pub first_version: String,
    pub last_version: String,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn get_metadata(&self) -> Result<&BlockMetadata, ApiError> {
        // Filter to only TypeA, collect into a Vec.
        let filtered: Vec<_> = self
            .transactions
            .iter()
            .filter(|e| matches!(e, Transaction::BlockMetadata(_)))
            .collect();

        // Verify there's exactly one element of type Transaction::BlockMetadata.
        if filtered.len() == 1 {
            // Extract the value (you know there's exactly one element).
            if let Transaction::BlockMetadata(val) = filtered[0] {
                return Ok(val); // Return the inner value of Transaction::BlockMetadata
            }
        }

        Err(ApiError::BlockMetadataNotFound {
            height: self.block_height.clone(),
        })
    }
}

#[derive(Debug, Serialize)]
pub enum Transaction {
    // Transaction that contains the metadata of the block that contains it.
    BlockMetadata(Box<BlockMetadata>),
    // Other types of transactions.
    Other(Value),
}

// Implement Deserialize manually for Transaction.
impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize the transaction as a generic Value first.
        let v = Value::deserialize(deserializer)?;

        // Check if it's a block_metadata_transaction by inspecting the type field.
        if let Some(map) = v.as_object() {
            if let Some(Value::String(type_str)) = map.get("type") {
                if type_str == "block_metadata_transaction" {
                    // Deserialize it as BlockMetadata.
                    return Ok(Transaction::BlockMetadata(
                        serde_json::from_value(v).map_err(de::Error::custom)?,
                    ));
                }
            }
        }

        // If not a BlockMetadata transaction, return it as Other.
        Ok(Transaction::Other(v))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockMetadata {
    #[serde(rename = "type")]
    r#type: String,
    id: String,
    epoch: String,
    round: String,
    version: String,
    hash: String,
    state_change_hash: String,
    accumulator_root_hash: String,
    event_root_hash: String,
    timestamp: String,
    proposer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OtherData {
    #[serde(flatten)]
    data: Value,
}

impl TryInto<BlockInfo> for Block {
    type Error = anyhow::Error;

    fn try_into(self) -> std::result::Result<BlockInfo, Self::Error> {
        let metadata = self.get_metadata().map_err(|e| anyhow::anyhow!(e))?;
        Ok(BlockInfo::new(
            metadata.epoch.parse()?,
            metadata.round.parse()?,
            HashValue::from_human_readable(&metadata.id).unwrap(),
            // TODO this is only for this tx, not the whole block
            HashValue::from_human_readable(&metadata.accumulator_root_hash).unwrap(),
            self.last_version.parse()?,
            self.block_timestamp.parse()?,
            // TODO where to find next_epoch_state?
            None,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fetch_block_with_metadata() {
        // Block https://explorer.aptoslabs.com/block/139691105/overview?network=mainnet
        let res = reqwest::blocking::get("https://fullnode.mainnet.aptoslabs.com/v1/blocks/by_height/139691105?with_transactions=true").unwrap().bytes().unwrap();
        let block: Block = serde_json::from_slice(&res).unwrap();

        let _block_info: BlockInfo = block.try_into().unwrap();
    }
}
