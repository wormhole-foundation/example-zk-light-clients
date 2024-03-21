// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use std::marker::PhantomData;

use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_core::boolean::Boolean;
use lurk::circuit::gadgets::pointer::AllocatedPtr;
use lurk::coprocessor::{CoCircuit, Coprocessor};
use lurk::field::LurkField;
use lurk::lem::circuit::GlobalAllocator;
use lurk::lem::pointers::Ptr;
use lurk::lem::store::Store;
use serde::{Deserialize, Serialize};

const NBR_VALIDATORS: usize = 131;
const VALIDATORS_LIST_LEN: usize = 1 + NBR_VALIDATORS * (32 + 49 + 8); // vec size + nbr_validators * (account address + pub key + voting power)
const OFFSET_VALIDATOR_LIST: usize = 8 // epoch
        + 8 // round
        + 32 // id
        + 32 // executed state id
        + 8 // version
        + 8 // timestamp
        + 1 // Some
        + 8 // epoch
        + 1; // next byte
const OFFSET_LEDGER_INFO: usize = 1; // not taking the variant byte
const LEDGER_INFO_LEN: usize = 8 // epoch
    + 8 // round
    + 32 // id
    + 32 // executed state id
    + 8 // version
    + 8 // timestamp
    + 1 // Some
    + 8 // epoch
    + VALIDATORS_LIST_LEN
    + 32; // consensus data hash

const OFFSET_SIGNATURE: usize = LEDGER_INFO_LEN + 1; // next byte
const SIGNATURE_LEN: usize = 1 + (NBR_VALIDATORS + 7) / 8 + 1 + 1 + 96;

/// Structure representing the bytes parser Coprocessor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BytesParser<F: LurkField> {
    _p: PhantomData<F>,
}

impl<F: LurkField> CoCircuit<F> for BytesParser<F> {
    /// Expect to receive a `LurkField` representing a list
    fn arity(&self) -> usize {
        1
    }

    fn synthesize_simple<CS: ConstraintSystem<F>>(
        &self,
        _cs: &mut CS,
        _g: &GlobalAllocator<F>,
        _s: &Store<F>,
        _not_dummy: &Boolean,
        _args: &[AllocatedPtr<F>],
    ) -> Result<AllocatedPtr<F>, SynthesisError> {
    }
}

impl<F: LurkField> Coprocessor<F> for BytesParser<F> {
    fn has_circuit(&self) -> bool {
        true
    }
    fn evaluate_simple(&self, _s: &Store<F>, _args: &[Ptr]) -> Ptr {
        todo!()
    }
}
