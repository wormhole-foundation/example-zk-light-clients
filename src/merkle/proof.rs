// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::crypto::circuit::chunk_step::ChunkStep;
use crate::crypto::circuit::{AptosCircuit, E1, S1, S2};
use crate::crypto::hash::HashValue;
use crate::merkle::node::SparseMerkleLeafNode;
use anyhow::ensure;
use arecibo::supernova::snark::CompressedSNARK;
use arecibo::supernova::{NonUniformCircuit, PublicParams, RecursiveSNARK};
use arecibo::traits::snark::default_ck_hint;
use arecibo::traits::{Dual, Engine};
use bellpepper::gadgets::multipack::bytes_to_bits;
use ff::Field;
use getset::Getters;

#[derive(Clone, Debug, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct SparseMerkleProof {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(leaf_node)`
    ///         - If `leaf_node.key` equals requested key, this is an inclusion proof and
    ///           `leaf_node.value_hash` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof, which we do not handle.
    ///     - If this is `None`, this is also a non-inclusion proof, which we do not handle in the light client.
    leaf: Option<SparseMerkleLeafNode>,

    /// All siblings in this proof, including the default ones. Siblings are ordered from the bottom
    /// level to the root level.
    siblings: Vec<HashValue>,
}

impl SparseMerkleProof {
    /// Verifies an element whose key is `element_key` and value is authenticated by `element_hash` exists in the Sparse
    /// Merkle Tree using the provided proof.
    /// # Note
    /// For now, the `N` parameter needs to represent the number of siblings to use in the proof verification multiplied by 3 in
    /// as each sibling inputs are 3 field elements.
    #[allow(dead_code)]
    pub fn verify_by_hash<const N: usize>(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: HashValue,
    ) -> anyhow::Result<()> {
        ensure!(
            self.siblings.len() <= 256,
            "Sparse Merkle Tree proof has more than {} ({}) siblings.",
            256,
            self.siblings.len(),
        );

        // Proof need to contain leaf if proof of inclusion
        let leaf = self.leaf.unwrap();

        ensure!(
            element_key == leaf.key(),
            "Keys do not match. Key in proof: {:x}. Expected key: {:x}. \
             Element hash: {:x}. Value hash in proof {:x}",
            leaf.key(),
            element_key,
            element_hash,
            leaf.value_hash()
        );

        ensure!(
            element_hash == leaf.value_hash(),
            "Value hashes do not match for key {:x}. Value hash in proof: {:x}. \
                     Expected value hash: {:x}. ",
            element_key,
            leaf.value_hash(),
            element_hash
        );

        let root_hash_elems: Vec<<E1 as Engine>::Scalar> = From::from(&expected_root_hash);
        let leaf_hash_elems: Vec<<E1 as Engine>::Scalar> = From::from(&element_hash);
        let leaf_key = bytes_to_bits(element_key.as_ref())
            .iter()
            .take(self.siblings().len())
            .map(|b| {
                if *b {
                    <E1 as Engine>::Scalar::ONE
                } else {
                    <E1 as Engine>::Scalar::ZERO
                }
            })
            .collect::<Vec<<E1 as Engine>::Scalar>>();

        let mut siblings_hash_key_elems: Vec<<E1 as Engine>::Scalar> = vec![];

        for (sibling, key) in self.siblings.iter().zip(leaf_key.into_iter()) {
            siblings_hash_key_elems.push(key);
            let mut sib_elems: Vec<<E1 as Engine>::Scalar> = From::from(sibling);
            siblings_hash_key_elems.append(&mut sib_elems);
        }
        // TODO move the circuit instantiation, recursive snark intantiation/proving, compressed snark instantiation/proving somewhere else

        let z0_primary: Vec<<E1 as Engine>::Scalar> =
            [leaf_hash_elems.as_slice(), root_hash_elems.as_slice()]
                .concat()
                .to_vec();
        let z0_secondary = vec![<Dual<E1> as Engine>::Scalar::ZERO];

        //  Primary circuit
        let chunk_circuit =
            <AptosCircuit<<E1 as Engine>::Scalar, ChunkStep<<E1 as Engine>::Scalar>, N>>::new(
                &siblings_hash_key_elems,
            );
        let circuit_primary = <AptosCircuit<
            halo2curves::bn256::Fr,
            ChunkStep<halo2curves::bn256::Fr>,
            N,
        > as NonUniformCircuit<E1>>::primary_circuit(
            &chunk_circuit, 0
        );
        let circuit_secondary = <AptosCircuit<
            <E1 as Engine>::Scalar,
            ChunkStep<<E1 as Engine>::Scalar>,
            N,
        > as NonUniformCircuit<E1>>::secondary_circuit(
            &chunk_circuit
        );

        let pp =
            PublicParams::<E1>::setup(&chunk_circuit, &*default_ck_hint(), &*default_ck_hint());

        let mut recursive_snark = RecursiveSNARK::<E1>::new(
            &pp,
            &chunk_circuit,
            &circuit_primary,
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        )
        .unwrap();

        // Number of chunk iter + hash equality
        for step in 0..siblings_hash_key_elems.len().div_ceil(N) + 1 {
            // Last iteration hash equality, otherwise chunk iter
            let circuit_primary = if step == siblings_hash_key_elems.len().div_ceil(N) {
                <AptosCircuit<
                    <E1 as Engine>::Scalar,
                    ChunkStep<<E1 as Engine>::Scalar>,
                    N,
                > as NonUniformCircuit<E1>>::primary_circuit(
                    &chunk_circuit, 1
                )
            } else {
                chunk_circuit.get_iteration_circuit(step)
            };

            let res = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
            assert!(res.is_ok());

            let res = recursive_snark.verify(&pp, &z0_primary, &z0_secondary);
            assert!(res.is_ok());
        }

        let (prover_key, verifier_key) = CompressedSNARK::<_, S1, S2>::setup(&pp).unwrap();

        let res = CompressedSNARK::<_, S1, S2>::prove(&pp, &prover_key, &recursive_snark);

        assert!(res.is_ok());
        let compressed_snark = res.unwrap();

        // verify the compressed SNARK
        let res = compressed_snark.verify(&pp, &verifier_key, &z0_primary, &z0_secondary);
        assert!(res.is_ok());

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::circuit::hash::Sha3;
    use bellpepper_merkle_inclusion::traits::GadgetDigest;
    use sha3::digest::Output;
    use sha3::Digest;

    /*use proptest::prelude::*;
    use proptest::proptest;*/

    pub fn hash<D: Digest>(data: &[u8]) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(data);

        hasher.finalize()
    }

    /*proptest! {
            #![proptest_config(ProptestConfig::with_cases(5))]


        #[test]
        fn test_verify_proof(
            leaf_node in any::<SparseMerkleLeafNode>(),
            siblings in prop::collection::vec(any::<HashValue>(), 5..15),
        ) {
            let proof = SparseMerkleProof {
                leaf: Some(leaf_node),
                siblings: siblings.clone(),
            };

            let key = leaf_node.key();
            let value_hash = leaf_node.value_hash();
            let expected_root_hash = siblings
                .iter()
                .zip(key.iter_bits().take(siblings.len()))
                .fold(leaf_node.value_hash(), |acc_hash, (sibling_hash, bit)| {
                    if bit {
                        HashValue::from_slice(hash::<
                            <Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher,
                        >(
                            &[sibling_hash.hash(), acc_hash.hash()].concat()
                        ))
                        .unwrap()
                    } else {
                        HashValue::from_slice(hash::<
                            <Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher,
                        >(
                            &[acc_hash.hash(), sibling_hash.hash()].concat()
                        ))
                        .unwrap()
                    }
                });

            proof
                .verify_by_hash::<3>(expected_root_hash, key, value_hash)
                .unwrap()
        }
    }*/

    #[test]
    fn test_verify_proof_simple() {
        // Leaf and root hashes
        let a_leaf_hash = hash::<<Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher>(
            "a".as_bytes(),
        );
        let b_leaf_hash = hash::<<Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher>(
            "b".as_bytes(),
        );
        let c_leaf_hash = hash::<<Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher>(
            "c".as_bytes(),
        );
        let d_leaf_hash = hash::<<Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher>(
            "d".as_bytes(),
        );

        let cd_leaf_hash = hash::<<Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher>(
            &[c_leaf_hash, d_leaf_hash].concat(),
        );

        let leaf_node = SparseMerkleLeafNode::new(
            HashValue::from_slice([
                128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ])
            .unwrap(),
            HashValue::from_slice(a_leaf_hash).unwrap(),
        );

        let siblings = vec![
            HashValue::from_slice(b_leaf_hash).unwrap(),
            HashValue::from_slice(cd_leaf_hash).unwrap(),
        ];

        let proof = SparseMerkleProof {
            leaf: Some(leaf_node),
            siblings: siblings.clone(),
        };

        let key = leaf_node.key();
        let value_hash = leaf_node.value_hash();
        let expected_root_hash = siblings
            .iter()
            .zip(key.iter_bits().take(siblings.len()))
            .fold(leaf_node.value_hash(), |acc_hash, (sibling_hash, bit)| {
                if bit {
                    HashValue::from_slice(hash::<
                        <Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher,
                    >(
                        &[sibling_hash.hash(), acc_hash.hash()].concat()
                    ))
                    .unwrap()
                } else {
                    HashValue::from_slice(hash::<
                        <Sha3 as GadgetDigest<<E1 as Engine>::Scalar>>::OutOfCircuitHasher,
                    >(
                        &[acc_hash.hash(), sibling_hash.hash()].concat()
                    ))
                    .unwrap()
                }
            });

        proof
            .verify_by_hash::<3>(expected_root_hash, key, value_hash)
            .unwrap()
    }
}
