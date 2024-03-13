use crate::crypto::circuit::chunk_step::ChunkStep;
use crate::crypto::circuit::AptosCircuit;
use arecibo::supernova::snark::{CompressedSNARK, ProverKey, VerifierKey};
use arecibo::supernova::{NonUniformCircuit, PublicParams, RecursiveSNARK};
use arecibo::traits::snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait};
use arecibo::traits::{CurveCycleEquipped, Dual, Engine};
use getset::Getters;

#[derive(Getters)]
#[getset(get = "pub")]
pub struct ProvingSystem<
    E1: CurveCycleEquipped,
    S1: BatchedRelaxedR1CSSNARKTrait<E1>,
    S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
    const N: usize,
> {
    circuit: AptosCircuit<<E1 as Engine>::Scalar, ChunkStep<<E1 as Engine>::Scalar>, N>,
    pp: PublicParams<E1>,
    recursive_snark: RecursiveSNARK<E1>,
    compressed_snark_prover_key: ProverKey<E1, S1, S2>,
    compressed_snark_verifier_key: VerifierKey<E1, S1, S2>,
    z0_primary: Vec<<E1 as Engine>::Scalar>,
    z0_secondary: Vec<<Dual<E1> as Engine>::Scalar>,
}

impl<
        E1: CurveCycleEquipped,
        S1: BatchedRelaxedR1CSSNARKTrait<E1>,
        S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
        const N: usize,
    > ProvingSystem<E1, S1, S2, N>
{
    pub fn new(
        circuit: AptosCircuit<<E1 as Engine>::Scalar, ChunkStep<<E1 as Engine>::Scalar>, N>,
        z0_primary: Vec<<E1 as Engine>::Scalar>,
        z0_secondary: Vec<<Dual<E1> as Engine>::Scalar>,
    ) -> Self {
        let pp = PublicParams::<E1>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor());
        let circuit_primary =
            <AptosCircuit<_, _, N> as NonUniformCircuit<E1>>::primary_circuit(&circuit, 0);
        let circuit_secondary =
            <AptosCircuit<_, _, N> as NonUniformCircuit<E1>>::secondary_circuit(&circuit);
        let recursive_snark = RecursiveSNARK::<E1>::new(
            &pp,
            &circuit,
            &circuit_primary,
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        )
        .unwrap();

        let (prover_key, verifier_key) = CompressedSNARK::<_, S1, S2>::setup(&pp).unwrap();

        Self {
            circuit,
            pp,
            recursive_snark,
            compressed_snark_prover_key: prover_key,
            compressed_snark_verifier_key: verifier_key,
            z0_primary,
            z0_secondary,
        }
    }

    pub fn recursive_proving(&mut self) {
        for step in 0..self.circuit.iteration_steps().len() + 1 {
            let circuit_primary = if step == self.circuit.iteration_steps().len() {
                <AptosCircuit<_, _, N> as NonUniformCircuit<E1>>::primary_circuit(&self.circuit, 1)
            } else {
                self.circuit.get_iteration_circuit(step)
            };

            let res = self.recursive_snark.prove_step(
                &self.pp,
                &circuit_primary,
                &<AptosCircuit<_, _, N> as NonUniformCircuit<E1>>::secondary_circuit(&self.circuit),
            );
            assert!(res.is_ok());
        }
    }

    pub fn compressed_proving(&self) -> CompressedSNARK<E1, S1, S2> {
        CompressedSNARK::<_, S1, S2>::prove(
            &self.pp,
            &self.compressed_snark_prover_key,
            &self.recursive_snark,
        )
        .unwrap()
    }

    pub fn compressed_verify(&self, compressed_snark: &CompressedSNARK<E1, S1, S2>) {
        compressed_snark
            .verify(
                &self.pp,
                &self.compressed_snark_verifier_key,
                &self.z0_primary,
                &self.z0_secondary,
            )
            .unwrap();
    }
}
