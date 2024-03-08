// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use arecibo::supernova::StepCircuit;
use bellpepper_chunk::traits::InnerIterationStepCircuit;
use bellpepper_chunk::IterationStep;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::PrimeField;
use getset::Getters;

/// Wrapper around the chunk `FoldStep` struct to make it compatible with the `StepCircuit` trait.
// TODO: once we have proper "recursive-pepper" crate, this should be imported from there.
#[derive(Clone, Debug, Getters)]
#[getset(get = "pub")]
pub struct IterationStepWrapper<F: PrimeField, C: InnerIterationStepCircuit<F>, const N: usize> {
    inner: IterationStep<F, C, N>,
}

impl<F: PrimeField, C: InnerIterationStepCircuit<F>, const N: usize> IterationStepWrapper<F, C, N> {
    pub fn new(iteration_step: IterationStep<F, C, N>) -> Self {
        Self {
            inner: iteration_step,
        }
    }
}

impl<F: PrimeField, C: InnerIterationStepCircuit<F>, const N: usize> StepCircuit<F>
    for IterationStepWrapper<F, C, N>
{
    fn arity(&self) -> usize {
        self.inner.arity()
    }

    fn circuit_index(&self) -> usize {
        *self.inner.circuit_index()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let (next_pc, res_inner_synth) =
            self.inner
                .synthesize(&mut cs.namespace(|| "iteration_step_wrapper"), pc, z)?;

        Ok((next_pc, res_inner_synth))
    }
}
