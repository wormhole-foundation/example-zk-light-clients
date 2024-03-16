// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::crypto::circuit::hash::hash_fields_to_bools;
use arecibo::supernova::StepCircuit;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_merkle_inclusion::hash_equality;
use ff::PrimeFieldBits;
use std::marker::PhantomData;

/// Placeholder struct to represent the hash equality `StepCircuit`.
#[derive(Clone, Debug, Default)]
pub struct HashEqualityCircuit<F: PrimeFieldBits> {
    _p: PhantomData<F>,
}

impl<F: PrimeFieldBits> StepCircuit<F> for HashEqualityCircuit<F> {
    fn arity(&self) -> usize {
        4
    }

    fn circuit_index(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        _pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let acc =
            hash_fields_to_bools(&mut cs.namespace(|| "reconstruct acc hash"), &z[0..2], 256)?;

        let root_hash =
            hash_fields_to_bools(&mut cs.namespace(|| "reconstruct root hash"), &z[2..4], 256)?;

        hash_equality(&mut cs.namespace(|| "hash_equality"), &acc, root_hash)?;

        Ok((
            Some(AllocatedNum::alloc(
                &mut cs.namespace(|| "no next circuit"),
                || Ok(F::ZERO),
            )?),
            z.to_vec(),
        ))
    }
}
