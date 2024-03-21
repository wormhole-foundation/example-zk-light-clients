// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use lurk::field::LurkField;
use lurk_macros::Coproc;

mod parser;
mod utils;

#[derive(Clone, Debug, Coproc)]
pub enum AptosCoproc<F: LurkField> {
    BytesParser(parser::AptosParser<F>),
}
