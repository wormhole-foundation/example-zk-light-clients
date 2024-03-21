// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
mod coprocessors;
pub mod crypto;
pub mod merkle;
pub mod types;
#[cfg(test)]
pub mod unit_tests;

// TODO change to aptos real validator count
pub const NBR_VALIDATORS: usize = 5;
