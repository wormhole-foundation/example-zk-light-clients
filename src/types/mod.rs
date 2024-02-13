// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use serde::{Serialize, Serializer};
use test_strategy::Arbitrary;

mod api;
pub mod block_info;
pub mod epoch_state;
pub mod error;
pub mod ledger_info;
pub mod trusted_state;
mod validator;
pub mod waypoint;

pub type Round = u64;
pub type Version = u64;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Copy, Arbitrary)]
pub struct AccountAddress([u8; 16]);

impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // See comment in deserialize.
        serializer.serialize_newtype_struct("AccountAddress", &self.0)
    }
}
