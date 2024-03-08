// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::crypto::circuit::equality::HashEqualityCircuit;
use crate::crypto::circuit::iteration_step_wrapper::IterationStepWrapper;
use arecibo::supernova::{NonUniformCircuit, StepCircuit, TrivialSecondaryCircuit};
use arecibo::traits::{CurveCycleEquipped, Dual, Engine};
use bellpepper_chunk::traits::InnerIterationStepCircuit;
use bellpepper_chunk::IterationStep;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::PrimeFieldBits;
use halo2curves::bn256::Bn256;

pub mod chunk_step;
pub mod equality;
pub mod hash;
pub mod iteration_step_wrapper;
pub mod utils;

pub type E1 = arecibo::provider::Bn256EngineKZG;
pub type E2 = arecibo::provider::GrumpkinEngine;
pub type EE1 = arecibo::provider::hyperkzg::EvaluationEngine<Bn256, E1>;
pub type EE2 = arecibo::provider::ipa_pc::EvaluationEngine<E2>;

pub type S1 = arecibo::spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;

pub type S2 = arecibo::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// Structure representing the set of sub-circuit to be proven by using Supernova.
pub struct AptosCircuit<F: PrimeFieldBits, C: InnerIterationStepCircuit<F>, const N: usize> {
    pub(crate) iteration_steps: Vec<IterationStep<F, C, N>>,
}

impl<F: PrimeFieldBits, C: InnerIterationStepCircuit<F>, const N: usize> AptosCircuit<F, C, N> {
    pub(crate) fn new(inputs: &[F]) -> Self {
        Self {
            // We expect EqualityCircuit to be called once the last `IterationStep` is done.
            iteration_steps: IterationStep::from_inputs(0, inputs, F::ONE),
        }
    }

    fn get_iteration_step(&self, step: usize) -> IterationStep<F, C, N> {
        self.iteration_steps[step].clone()
    }

    pub(crate) fn get_iteration_circuit(&self, step: usize) -> ChunkCircuitSet<F, C, N> {
        ChunkCircuitSet::IterationStep(IterationStepWrapper::new(self.get_iteration_step(step)))
    }
}

#[derive(Clone, Debug)]
pub enum ChunkCircuitSet<F: PrimeFieldBits, C: InnerIterationStepCircuit<F>, const N: usize> {
    IterationStep(IterationStepWrapper<F, C, N>),
    CheckEquality(HashEqualityCircuit<F>),
}

impl<F: PrimeFieldBits, C: InnerIterationStepCircuit<F>, const N: usize> StepCircuit<F>
    for ChunkCircuitSet<F, C, N>
{
    fn arity(&self) -> usize {
        match self {
            Self::IterationStep(iteration_step) => iteration_step.inner().arity(),
            Self::CheckEquality(equality_circuit) => equality_circuit.arity(),
        }
    }

    fn circuit_index(&self) -> usize {
        match self {
            Self::IterationStep(iteration_step) => *iteration_step.inner().circuit_index(),
            Self::CheckEquality(equality_circuit) => equality_circuit.circuit_index(),
        }
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        match self {
            Self::IterationStep(iteration_step) => iteration_step.synthesize(cs, pc, z),
            Self::CheckEquality(equality_circuit) => equality_circuit.synthesize(cs, pc, z),
        }
    }
}

impl<E1: CurveCycleEquipped, C: InnerIterationStepCircuit<E1::Scalar>, const N: usize>
    NonUniformCircuit<E1> for AptosCircuit<E1::Scalar, C, N>
{
    type C1 = ChunkCircuitSet<E1::Scalar, C, N>;
    type C2 = TrivialSecondaryCircuit<<Dual<E1> as Engine>::Scalar>;

    fn num_circuits(&self) -> usize {
        2
    }

    fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
        match circuit_index {
            0 => self.get_iteration_circuit(0),
            1 => Self::C1::CheckEquality(HashEqualityCircuit::default()),
            _ => panic!("No circuit found for index {}", circuit_index),
        }
    }

    fn secondary_circuit(&self) -> Self::C2 {
        Default::default()
    }
}
