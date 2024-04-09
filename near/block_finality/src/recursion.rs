use anyhow::Result;
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;

/// Recursively aggregates two proofs to one, verifies inner proofs and optionally set public inputs.
pub fn recursive_proof<F, C, InnerC, const D: usize>(
    (first_inner_common, first_inner_verifier, first_inner_proof): (
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<InnerC, D>,
        &ProofWithPublicInputs<F, InnerC, D>,
    ),
    second_inner_data_proof: Option<(
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<InnerC, D>,
        &ProofWithPublicInputs<F, InnerC, D>,
    )>,
    public_inputs: Option<&[F]>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F=F>,
        InnerC: GenericConfig<D, F=F>,
        InnerC::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(first_inner_common);
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(first_inner_common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, first_inner_proof);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &first_inner_verifier.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        first_inner_verifier.circuit_digest,
    );
    builder.verify_proof::<InnerC>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        first_inner_common,
    );
    if second_inner_data_proof.is_some() {
        let proof_with_pis_target_2 =
            builder.add_virtual_proof_with_pis(second_inner_data_proof.unwrap().0);
        let verifier_circuit_target_2 = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(
                second_inner_data_proof
                    .unwrap()
                    .0
                    .config
                    .fri_config
                    .cap_height,
            ),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target_2, second_inner_data_proof.unwrap().2);
        pw.set_cap_target(
            &verifier_circuit_target_2.constants_sigmas_cap,
            &second_inner_data_proof.unwrap().1.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target_2.circuit_digest,
            second_inner_data_proof.unwrap().1.circuit_digest,
        );
        builder.verify_proof::<InnerC>(
            &proof_with_pis_target_2,
            &verifier_circuit_target_2,
            second_inner_data_proof.unwrap().0,
        );
    }
    if let Some(pi) = public_inputs {
        let pi_targets: Vec<Target> = builder.add_virtual_targets(pi.len());
        for i in 0..pi.len() {
            pw.set_target(pi_targets[i], pi[i]);
            builder.register_public_input(pi_targets[i]);
        }
    }
    let data_new = builder.build::<C>();
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof_new: ProofWithPublicInputs<F, C, D> =
        prove(&data_new.prover_only, &data_new.common, pw, &mut timing)?;

    //timing.print();

    Ok((data_new, proof_new))
}

/// Aggregates recursively array of proofs.
pub fn recursive_proofs<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    data_proofs: &[(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)],
    public_inputs: Option<&[F]>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
    where
        C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::new();
    for i in 0..data_proofs.len() {
        let proof_with_pis_target = builder.add_virtual_proof_with_pis(&data_proofs[i].0.common);
        let verifier_circuit_target = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(data_proofs[i].0.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target, &data_proofs[i].1);
        pw.set_cap_target(
            &verifier_circuit_target.constants_sigmas_cap,
            &data_proofs[i].0.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target.circuit_digest,
            data_proofs[i].0.verifier_only.circuit_digest,
        );
        builder.verify_proof::<C>(
            &proof_with_pis_target,
            &verifier_circuit_target,
            &data_proofs[i].0.common,
        );
    }
    if let Some(pi) = public_inputs {
        let pi_targets: Vec<Target> = builder.add_virtual_targets(pi.len());
        for i in 0..pi.len() {
            pw.set_target(pi_targets[i], pi[i]);
            builder.register_public_input(pi_targets[i]);
        }
    }
    let timing = TimingTree::new("build", Level::Debug);
    let data_new = builder.build::<C>();
    timing.print();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new: ProofWithPublicInputs<F, C, D> = data_new.prove(pw)?;
    timing.print();
    Ok((data_new, proof_new))
}

/// Aggregate recursively proofs reusing proving scheme.
pub fn recursive_proofs_reuse_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    circuit: &CircuitData<F, C, D>,
    proofs: &[ProofWithPublicInputs<F, C, D>],
    public_inputs: Option<&[F]>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
    where
        C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::new();
    for proof in proofs {
        let proof_with_pis_target = builder.add_virtual_proof_with_pis(&circuit.common);
        let verifier_circuit_target = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(circuit.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target, proof);
        pw.set_cap_target(
            &verifier_circuit_target.constants_sigmas_cap,
            &circuit.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target.circuit_digest,
            circuit.verifier_only.circuit_digest,
        );
        builder.verify_proof::<C>(
            &proof_with_pis_target,
            &verifier_circuit_target,
            &circuit.common,
        );
    }
    if let Some(pi) = public_inputs {
        let pi_targets: Vec<Target> = builder.add_virtual_targets(pi.len());
        for i in 0..pi.len() {
            pw.set_target(pi_targets[i], pi[i]);
            builder.register_public_input(pi_targets[i]);
        }
    }
    let timing = TimingTree::new("build", Level::Debug);
    let data_new = builder.build::<C>();
    timing.print();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new: ProofWithPublicInputs<F, C, D> = data_new.prove(pw)?;
    timing.print();
    Ok((data_new, proof_new))
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_field::types::Field;
    use crate::prove_primitives::two_thirds;
    use super::*;

    #[test]
    fn test_recursive_proof_valid() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let (cd, proof) = two_thirds::<F, C, D>(&v_bits, &v_i_bits)?;
        cd.verify(proof.clone())?;

        let recursive_data = recursive_proof::<F, C, C, D>(
            (&cd.common, &cd.verifier_only, &proof),
            None,
            None,
        );
        assert!(recursive_data.is_ok());
        let (recursive_cd, recursive_proof) = recursive_data?;
        assert!(recursive_cd.verify(recursive_proof).is_ok());
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_recursive_proof_invalid() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let (cd, proof) = two_thirds::<F, C, D>(&v_bits, &v_i_bits).unwrap();
        cd.verify(proof.clone()).unwrap();
        let mut modified_proof = proof.clone();

        modified_proof.public_inputs[proof.public_inputs.len() - 1] = F::from_canonical_u64(10000);

        let recursive_data = recursive_proof::<F, C, C, D>(
            (&cd.common, &cd.verifier_only, &modified_proof),
            None,
            None,
        ).unwrap();
    }

    #[test]
    fn test_recursive_proofs_valid() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let lhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits)?;
        let rhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits)?;

        let data_proofs = vec![lhs_data, rhs_data];

        let recursive_data = recursive_proofs::<F, C, D>(&data_proofs, None);
        assert!(recursive_data.is_ok());
        let (recursive_cd, recursive_proof) = recursive_data?;
        assert!(recursive_cd.verify(recursive_proof).is_ok());
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_recursive_proofs_invalid() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let lhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits).unwrap();
        let rhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits).unwrap();

        let (_, mut modified_proof) = rhs_data.clone();

        modified_proof.public_inputs[rhs_data.1.public_inputs.len() - 1] = F::from_canonical_u64(10000);

        let data_proofs = vec![lhs_data, (rhs_data.0, modified_proof)];

        let recursive_data = recursive_proofs::<F, C, D>(&data_proofs, None);
        let (recursive_cd, recursive_proof) = recursive_data.unwrap();
        recursive_cd.verify(recursive_proof).unwrap();
    }

    #[test]
    fn test_recursive_proofs_reuse_circuit_valid()  -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let lhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits)?;
        let rhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits)?;

        let proofs = vec![lhs_data.1, rhs_data.1];

        let recursive_data = recursive_proofs_reuse_circuit::<F, C, D>(&lhs_data.0, &proofs, None);
        assert!(recursive_data.is_ok());
        let (recursive_cd, recursive_proof) = recursive_data?;
        assert!(recursive_cd.verify(recursive_proof).is_ok());
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_recursive_proofs_reuse_circuit_invalid() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let lhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits).unwrap();
        let rhs_data = two_thirds::<F, C, D>(&v_bits, &v_i_bits).unwrap();

        let (_, mut modified_proof) = rhs_data.clone();

        modified_proof.public_inputs[rhs_data.1.public_inputs.len() - 1] = F::from_canonical_u64(10000);
        let proofs = vec![lhs_data.1, modified_proof];

        let recursive_data = recursive_proofs_reuse_circuit::<F, C, D>(&lhs_data.0, &proofs, None);
        let (recursive_cd, recursive_proof) = recursive_data.unwrap();
        recursive_cd.verify(recursive_proof).unwrap();
    }
}





