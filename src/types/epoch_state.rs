// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use crate::types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use crate::types::validator::ValidatorVerifier;
use anyhow::ensure;
use serde::Serialize;
use test_strategy::Arbitrary;

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Arbitrary)]
pub struct EpochState {
    pub epoch: u64,
    pub verifier: ValidatorVerifier,
}

impl EpochState {
    pub fn epoch_change_verification_required(&self, epoch: u64) -> bool {
        self.epoch < epoch
    }

    pub fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        ledger_info.epoch() < self.epoch
    }

    pub fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
}
