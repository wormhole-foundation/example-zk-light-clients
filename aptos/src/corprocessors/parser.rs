// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use std::marker::PhantomData;

use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_core::boolean::Boolean;
use lurk::circuit::gadgets::pointer::AllocatedPtr;
use lurk::coprocessor::{CoCircuit, Coprocessor};
use lurk::coprocessor::gadgets::{chain_car_cdr, construct_list};
use lurk::field::LurkField;
use lurk::lem::circuit::GlobalAllocator;
use lurk::lem::pointers::Ptr;
use lurk::lem::store::Store;
use serde::{Deserialize, Serialize};

use crate::corprocessors::utils::extract_slices;

/// Structure representing the bytes parser Coprocessor
#[derive(Clone, Debug, Serialize, Deserialize)]
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

        let list = construct_list(cs, g, s, &extracted_ptr, None)?;

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

        let extracted_bits = extract_slices(
            &bits,
            &[
                (OFFSET_LEDGER_INFO, LEDGER_INFO_LEN),
                (OFFSET_VALIDATOR_LIST, VALIDATORS_LIST_LEN),
                (OFFSET_SIGNATURE, SIGNATURE_LEN),
            ],
        );

        s.list(extracted_bits)
    }
}
