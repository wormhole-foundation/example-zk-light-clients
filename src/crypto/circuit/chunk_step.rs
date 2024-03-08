// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use crate::crypto::circuit::hash::{hash_bools_to_fields, hash_fields_to_bools, Sha3};
use crate::crypto::circuit::utils::conditionally_select_vec;
use bellpepper_chunk::traits::InnerIterationStepCircuit;
use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_merkle_inclusion::conditional_hash;
use ff::{PrimeField, PrimeFieldBits};
use std::marker::PhantomData;

/// Placeholder structure representing the synthesising that happens in one chunk step.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ChunkStep<F: PrimeField> {
    _p: PhantomData<F>,
}

impl<F: PrimeFieldBits> InnerIterationStepCircuit<F> for ChunkStep<F> {
    fn new() -> Self {
        Self {
            _p: Default::default(),
        }
    }

    // Expected inputs for our circuit. We expect 4 inputs:
    // 1. The first field element of the leaf hash
    // 2. The second field element of the leaf hash
    // 3. The first field element of the root hash
    // 4. The second field element of the root hash
    fn arity() -> usize {
        4
    }

    // In this case z contains the value described above while chunk_in contains the intermediate hashes to continue
    // the computation.
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        _pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
        chunk_in: &[(Boolean, F)],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let mut acc =
            hash_fields_to_bools(&mut cs.namespace(|| "reconstruct acc hash"), &z[0..2], 256)?;

        // The inputs we handle for one inner iterations are multiple of 3.
        for (i, chunk) in chunk_in.chunks(3).enumerate() {
            let positional_bit = Boolean::Is(AllocatedBit::alloc(
                cs.namespace(|| format!("intermediate input {i} alloc boolean")),
                Some(chunk[0].1.to_le_bits()[0]),
            )?);
            let allocated_siblings = chunk[1..3]
                .iter()
                .enumerate()
                .map(|(j, (_, e))| {
                    AllocatedNum::alloc(
                        cs.namespace(|| format!("intermediate input {i} alloc chunk input {j}")),
                        || Ok(*e),
                    )
                    .unwrap()
                })
                .collect::<Vec<AllocatedNum<F>>>();

            let sibling = hash_fields_to_bools(
                &mut cs.namespace(|| format!("intermediate input {i} reconstruct_sibling_hash")),
                &allocated_siblings,
                256,
            )?;

            let next_acc = conditional_hash::<_, _, Sha3>(
                &mut cs.namespace(|| format!("intermediate input {i} conditional_hash")),
                &acc,
                &sibling,
                &positional_bit,
            )?;

            acc = conditionally_select_vec(
                cs.namespace(|| format!("intermediate input {i} conditional_select acc")),
                &next_acc,
                &acc,
                &chunk[0].0,
            )?;
        }

        let mut hash_fields = hash_bools_to_fields(&mut cs.namespace(|| "reconstruct hash"), &acc)?;

        hash_fields.extend_from_slice(&z[2..4]);

        Ok(hash_fields)
    }
}
