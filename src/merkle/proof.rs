// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::crypto::hash::create_literal_hash;
use crate::crypto::hash::{hash_data, CryptoHash, HashValue};
use crate::merkle::node::SparseMerkleLeafNode;
use anyhow::ensure;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseMerkleProof {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(leaf_node)`
    ///         - If `leaf_node.key` equals requested key, this is an inclusion proof and
    ///           `leaf_node.value_hash` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof. `leaf_node.key` is the only key
    ///           that exists in the subtree and `leaf_node.value_hash` equals the hash of the
    ///           corresponding account blob.
    ///     - If this is `None`, this is also a non-inclusion proof which indicates the subtree is
    ///       empty.
    leaf: Option<SparseMerkleLeafNode>,

    /// All siblings in this proof, including the default ones. Siblings are ordered from the bottom
    /// level to the root level.
    siblings: Vec<HashValue>,
}

impl SparseMerkleProof {
    /// If `element_hash` is present, verifies an element whose key is `element_key` and value is
    /// authenticated by `element_hash` exists in the Sparse Merkle Tree using the provided proof.
    /// Otherwise verifies the proof is a valid non-inclusion proof that shows this key doesn't
    /// exist in the tree.
    // TODO this should invoke our bellpepper gadget
    #[allow(dead_code)]
    pub fn verify_by_hash(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: Option<HashValue>,
    ) -> anyhow::Result<()> {
        ensure!(
            self.siblings.len() <= 256,
            "Sparse Merkle Tree proof has more than {} ({}) siblings.",
            256,
            self.siblings.len(),
        );

        match (element_hash, self.leaf) {
            (Some(hash), Some(leaf)) => {
                // This is an inclusion proof, so the key and value hash provided in the proof
                // should match element_key and element_value_hash. `siblings` should prove the
                // route from the leaf node to the root.
                ensure!(
                    element_key == leaf.key(),
                    "Keys do not match. Key in proof: {:x}. Expected key: {:x}. \
                     Element hash: {:x}. Value hash in proof {:x}",
                    leaf.key(),
                    element_key,
                    hash,
                    leaf.value_hash()
                );
                ensure!(
                    hash == leaf.value_hash(),
                    "Value hashes do not match for key {:x}. Value hash in proof: {:x}. \
                     Expected value hash: {:x}. ",
                    element_key,
                    leaf.value_hash(),
                    hash
                );
            }
            _ => {
                panic!("We only handle inclusion proofs in this function.")
            }
        }

        let current_hash = self.leaf.map_or(
            create_literal_hash("SPARSE_MERKLE_PLACEHOLDER_HASH"),
            |leaf| leaf.hash(),
        );
        let actual_root_hash = self
            .siblings
            .iter()
            .zip(
                element_key
                    .iter_bits()
                    .rev()
                    .skip(256 - self.siblings.len()),
            )
            .fold(current_hash, |hash, (sibling_hash, bit)| {
                if bit {
                    HashValue::new(hash_data(&sibling_hash.hash(), vec![&hash.hash()]))
                } else {
                    HashValue::new(hash_data(&hash.hash(), vec![&sibling_hash.hash()]))
                }
            });
        ensure!(
            actual_root_hash == expected_root_hash,
            "{}: Root hashes do not match. Actual root hash: {:x}. Expected root hash: {:x}.",
            "SparseMerkleProof",
            actual_root_hash,
            expected_root_hash,
        );

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeInProof {
    Leaf(SparseMerkleLeafNode),
    Other(HashValue),
}

impl From<HashValue> for NodeInProof {
    fn from(hash: HashValue) -> Self {
        Self::Other(hash)
    }
}

impl From<SparseMerkleLeafNode> for NodeInProof {
    fn from(leaf: SparseMerkleLeafNode) -> Self {
        Self::Leaf(leaf)
    }
}

impl CryptoHash for NodeInProof {
    fn hash(&self) -> HashValue {
        match self {
            Self::Leaf(leaf) => leaf.hash(),
            Self::Other(hash) => *hash,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::hash::hash_data;
    use proptest::prelude::*;
    use proptest::proptest;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn test_sparse_merkle_proof(
            leaf_node in any::<SparseMerkleLeafNode>(),
            siblings in prop::collection::vec(any::<HashValue>(), 0..256),
        ) {
            let proof = SparseMerkleProof {
                leaf: Some(leaf_node),
                siblings: siblings.clone(),
            };

            let key = leaf_node.key();
            let value_hash = leaf_node.value_hash();
            let expected_root_hash = siblings.iter().zip(
                key.iter_bits().rev().skip(256 - siblings.len())
            ).fold(
                leaf_node.hash(),
                |hash, (sibling_hash, bit)| {
                    if bit {
                        HashValue::new(hash_data(&sibling_hash.hash(), vec![&hash.hash()]))
                    } else {
                        HashValue::new(hash_data(&hash.hash(), vec![&sibling_hash.hash()]))
                    }
                }
            );

            proof.verify_by_hash(expected_root_hash, key, Some(value_hash)).unwrap();
        }
    }
}
