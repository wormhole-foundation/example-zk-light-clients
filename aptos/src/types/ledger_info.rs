// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use std::ops::Deref;

use getset::Getters;
use serde::{Deserialize, Serialize};
use test_strategy::Arbitrary;

use crate::crypto::hash::{CryptoHash, hash_data, HashValue, prefixed_sha3};
use crate::crypto::sig::AggregateSignature;
use crate::NBR_VALIDATORS;
use crate::types::block_info::BlockInfo;
use crate::types::epoch_state::EpochState;
use crate::types::error::VerifyError;
use crate::types::validator::ValidatorVerifier;
use crate::types::Version;

pub const OFFSET_VALIDATOR_LIST: usize = (8 // epoch
    + 8 // round
    + 32 // id
    + 32 // executed state id
    + 8 // version
    + 8 // timestamp
    + 1 // Some
    + 8 // epoch
    + 1)
    * 8; // next byte
pub const VALIDATORS_LIST_LEN: usize = (1 + NBR_VALIDATORS * (32 + 49 + 8)) * 8; // vec size + nbr_validators * (account address + pub key + voting power)
pub const OFFSET_LEDGER_INFO: usize = 8; // not taking the variant byte
pub const LEDGER_INFO_LEN: usize = (8 // epoch
        + 8 // round
        + 32 // id
        + 32 // executed state id
        + 8 // version
        + 8 // timestamp
        + 1 // Some
        + 8 // epoch
        + 32)
    * 8
    + VALIDATORS_LIST_LEN; // consensus data hash
pub const OFFSET_SIGNATURE: usize = LEDGER_INFO_LEN + 8; // next byte
pub const SIGNATURE_LEN: usize = (1 + (NBR_VALIDATORS + 7) / 8 + 1 + 1 + 96) * 8;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Arbitrary)]
pub struct LedgerInfo {
    commit_info: BlockInfo,
    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl LedgerInfo {
    pub fn new(commit_info: BlockInfo, consensus_data_hash: HashValue) -> Self {
        Self {
            commit_info,
            consensus_data_hash,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.commit_info.epoch()
    }

    pub fn next_block_epoch(&self) -> u64 {
        self.commit_info.next_block_epoch()
    }

    pub fn next_epoch_state(&self) -> Option<&EpochState> {
        self.commit_info.next_epoch_state().as_ref()
    }

    pub fn timestamp_usecs(&self) -> u64 {
        self.commit_info.timestamp_usecs()
    }

    pub fn transaction_accumulator_hash(&self) -> HashValue {
        self.commit_info.executed_state_id()
    }

    pub fn version(&self) -> Version {
        self.commit_info.version()
    }
}

impl CryptoHash for LedgerInfo {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"LedgerInfo"),
            vec![&bcs::to_bytes(&self).unwrap()],
        ))
    }
}

#[derive(Debug, Getters, PartialEq, Eq, Arbitrary, Serialize, Deserialize)]
pub struct LedgerInfoWithV0 {
    #[getset(get = "pub")]
    ledger_info: LedgerInfo,
    /// Aggregated BLS signature of all the validators that signed the message. The bitmask in the
    /// aggregated signature can be used to find out the individual validators signing the message
    signatures: AggregateSignature,
}

impl LedgerInfoWithV0 {
    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }
}

#[derive(Debug, PartialEq, Eq, Arbitrary, Serialize, Deserialize)]
pub enum LedgerInfoWithSignatures {
    V0(LedgerInfoWithV0),
}

// This deref polymorphism anti-pattern is in the upstream code (!)
impl Deref for LedgerInfoWithSignatures {
    type Target = LedgerInfoWithV0;

    fn deref(&self) -> &LedgerInfoWithV0 {
        match &self {
            LedgerInfoWithSignatures::V0(ledger) => ledger,
        }
    }
}

#[cfg(test)]
mod test {
    use tiny_keccak::{Hasher, Sha3};

    use crate::crypto::hash::prefixed_sha3;

    use super::*;

    #[test]
    fn test_hash() {
        let ledger_info = LedgerInfo {
            commit_info: BlockInfo::default(),
            consensus_data_hash: HashValue::default(),
        };

        let expected = {
            let mut digest = Sha3::v256();
            digest.update(&prefixed_sha3(b"LedgerInfo"));
            digest.update(&bcs::to_bytes(&ledger_info).unwrap());
            let mut hasher_bytes = [0u8; 32];
            digest.finalize(&mut hasher_bytes);
            hasher_bytes
        };

        let actual = ledger_info.hash();

        assert_eq!(expected, actual.hash());
    }
}
