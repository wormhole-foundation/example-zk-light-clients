// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use getset::CopyGetters;
use test_strategy::Arbitrary;

#[derive(Clone, Copy, Debug, Eq, PartialEq, CopyGetters, Arbitrary)]
pub struct SparseMerkleLeafNode {
    #[getset(get_copy = "pub")]
    key: HashValue,
    #[getset(get_copy = "pub")]
    value_hash: HashValue,
}

impl SparseMerkleLeafNode {
    pub fn new(key: HashValue, value_hash: HashValue) -> Self {
        Self { key, value_hash }
    }
}

impl CryptoHash for SparseMerkleLeafNode {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"SparseMerkleLeafNode"),
            vec![&self.key.hash(), &self.value_hash.hash()],
        ))
    }
}

pub struct SparseMerkleInternalNode {
    left_child: HashValue,
    right_child: HashValue,
}

impl CryptoHash for SparseMerkleInternalNode {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"SparseMerkleInternal"),
            vec![&self.left_child.hash(), &self.right_child.hash()],
        ))
    }
}
