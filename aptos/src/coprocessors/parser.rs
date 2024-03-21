// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use std::marker::PhantomData;

use bellpepper_core::boolean::Boolean;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use lurk::circuit::gadgets::pointer::AllocatedPtr;
use lurk::coprocessor::gadgets::{chain_car_cdr, construct_list};
use lurk::coprocessor::{CoCircuit, Coprocessor};
use lurk::field::LurkField;
use lurk::lem::circuit::GlobalAllocator;
use lurk::lem::pointers::Ptr;
use lurk::lem::store::Store;
use serde::{Deserialize, Serialize};

use crate::coprocessors::utils::extract_slices;

#[allow(dead_code)]
const APTOS_PARSER_SYM: &str = "aptos_parser";

/// Structure representing the bytes parser Coprocessor
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AptosParser<
    F: LurkField,
    const OFFSET_LEDGER_INFO: usize = { crate::types::ledger_info::OFFSET_LEDGER_INFO },
    const LEDGER_INFO_LEN: usize = { crate::types::ledger_info::LEDGER_INFO_LEN },
    const OFFSET_VALIDATOR_LIST: usize = { crate::types::ledger_info::OFFSET_VALIDATOR_LIST },
    const VALIDATORS_LIST_LEN: usize = { crate::types::ledger_info::VALIDATORS_LIST_LEN },
    const OFFSET_SIGNATURE: usize = { crate::types::ledger_info::OFFSET_SIGNATURE },
    const SIGNATURE_LEN: usize = { crate::types::ledger_info::SIGNATURE_LEN },
> {
    _p: PhantomData<F>,
}

impl<
        F: LurkField,
        const OFFSET_LEDGER_INFO: usize,
        const LEDGER_INFO_LEN: usize,
        const OFFSET_VALIDATOR_LIST: usize,
        const VALIDATORS_LIST_LEN: usize,
        const OFFSET_SIGNATURE: usize,
        const SIGNATURE_LEN: usize,
    > CoCircuit<F>
    for AptosParser<
        F,
        OFFSET_LEDGER_INFO,
        LEDGER_INFO_LEN,
        OFFSET_VALIDATOR_LIST,
        VALIDATORS_LIST_LEN,
        OFFSET_SIGNATURE,
        SIGNATURE_LEN,
    >
{
    /// Expect to receive a `LurkField` representing a list
    fn arity(&self) -> usize {
        1
    }

    fn synthesize_simple<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        g: &GlobalAllocator<F>,
        s: &Store<F>,
        not_dummy: &Boolean,
        args: &[AllocatedPtr<F>],
    ) -> Result<AllocatedPtr<F>, SynthesisError> {
        let total_size = 8 + LEDGER_INFO_LEN + SIGNATURE_LEN;
        // Get all bits of the message
        let (bits_alloc_ptr, _, _) =
            chain_car_cdr(cs, g, s, not_dummy, &args[0], total_size, false)?;

        let extracted_ptr = extract_slices(
            &bits_alloc_ptr,
            &[
                (OFFSET_LEDGER_INFO, LEDGER_INFO_LEN),
                (OFFSET_VALIDATOR_LIST, VALIDATORS_LIST_LEN),
                (OFFSET_SIGNATURE, SIGNATURE_LEN),
            ],
        );

        let ptrs_list = extracted_ptr
            .iter()
            .map(|bits| construct_list(cs, g, s, bits, None))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let list = construct_list(cs, g, s, &ptrs_list, None)?;

        Ok(list)
    }
}

impl<
        F: LurkField,
        const OFFSET_LEDGER_INFO: usize,
        const LEDGER_INFO_LEN: usize,
        const OFFSET_VALIDATOR_LIST: usize,
        const VALIDATORS_LIST_LEN: usize,
        const OFFSET_SIGNATURE: usize,
        const SIGNATURE_LEN: usize,
    > Coprocessor<F>
    for AptosParser<
        F,
        OFFSET_LEDGER_INFO,
        LEDGER_INFO_LEN,
        OFFSET_VALIDATOR_LIST,
        VALIDATORS_LIST_LEN,
        OFFSET_SIGNATURE,
        SIGNATURE_LEN,
    >
{
    fn has_circuit(&self) -> bool {
        true
    }
    fn evaluate_simple(&self, s: &Store<F>, args: &[Ptr]) -> Ptr {
        assert_eq!(
            args.len(),
            1,
            "AptosParser: Expected to receive a pointer to a list"
        );

        let (bits, _) = s
            .fetch_list(&args[0])
            .expect("AptosParser: Failed to retrieve bit list from given pointer");
        dbg!(bits.len());
        dbg!((OFFSET_LEDGER_INFO, LEDGER_INFO_LEN));
        dbg!((OFFSET_VALIDATOR_LIST, VALIDATORS_LIST_LEN));
        dbg!((OFFSET_SIGNATURE, SIGNATURE_LEN));
        let extracted_bits = extract_slices(
            &bits,
            &[
                (OFFSET_LEDGER_INFO, LEDGER_INFO_LEN),
                (OFFSET_VALIDATOR_LIST, VALIDATORS_LIST_LEN),
                (OFFSET_SIGNATURE, SIGNATURE_LEN),
            ],
        );

        s.list(
            extracted_bits
                .into_iter()
                .map(|bits| s.list(bits))
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use std::sync::Arc;

    use bellpepper::gadgets::multipack::bytes_to_bits_le;
    use halo2curves::bn256::Fr as Scalar;
    use itertools::Itertools;
    use lurk::dual_channel::dummy_terminal;
    use lurk::lang::Lang;
    use lurk::lem::eval::{
        evaluate, make_cprocs_funcs_from_lang, make_eval_step_from_config, EvalConfig,
    };
    use lurk::proof::supernova::SuperNovaProver;
    use lurk::proof::RecursiveSNARKTrait;
    use lurk::public_parameters::instance::Instance;
    use lurk::public_parameters::supernova_public_params;
    use lurk::state::user_sym;

    use crate::coprocessors::AptosCoproc;
    use crate::unit_tests::aptos::wrapper::AptosWrapper;
    use crate::NBR_VALIDATORS;

    use super::*;

    const REDUCTION_COUNT: usize = 1;

    fn lurk_program<F: LurkField>(store: &Store<F>, input: Vec<u8>) -> Ptr {
        let program = format!(
            r#"
            ({APTOS_PARSER_SYM} '({}))
        "#,
            input.iter().map(|b| format!("{b}")).join(" ")
        );

        store.read_with_default_state(&program).unwrap()
    }

    #[test]
    fn test_extract() {
        // Get command line input
        let args = std::env::args().collect::<Vec<_>>();

        // Initialize store, responsible for handling variables in the lurk context
        let store: Arc<Store<Scalar>> = Arc::new(Store::default());

        // Get LedgerInfoWithSignatures froù AptosWrapper
        let mut aptos_wrapper = AptosWrapper::new(1, NBR_VALIDATORS);
        aptos_wrapper.commit_new_epoch();
        dbg!(aptos_wrapper.get_latest_li().unwrap());
        let li_bytes = aptos_wrapper.get_latest_li_bytes().unwrap();

        let li_le_bits: Vec<u8> = bytes_to_bits_le(&li_bytes)
            .iter()
            .map(|b| *b as u8)
            .collect();
        dbg!(li_le_bits.len());
        // Create a pointer to the lurk program
        let program = lurk_program(&*store, li_le_bits);

        // Setup the lang to be able to use our Coprocessor
        let mut lang = Lang::<Scalar, AptosCoproc<Scalar>>::new();
        lang.add_coprocessor(user_sym(APTOS_PARSER_SYM), AptosParser::<Scalar>::default());

        let lurk_step = make_eval_step_from_config(&EvalConfig::new_nivc(&lang));
        let cprocs = make_cprocs_funcs_from_lang(&lang);

        // Evaluate the program
        let frames = evaluate(
            Some((&lurk_step, &cprocs, &lang)),
            program,
            &*store,
            1000,
            &dummy_terminal(),
        )
        .unwrap();

        // Instantiate prover
        let supernova_prover =
            SuperNovaProver::<Scalar, AptosCoproc<Scalar>>::new(REDUCTION_COUNT, Arc::new(lang));
        let instance = Instance::new_supernova(&supernova_prover, true);
        let pp = supernova_public_params(&instance).unwrap();

        // Proving
        let (proof, z0, zi, _) = supernova_prover
            .prove_from_frames(&pp, &frames, &store, None)
            .unwrap();

        // Verifying
        assert!(proof.verify(&pp, &z0, &zi).unwrap());
    }
}
