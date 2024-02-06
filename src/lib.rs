// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
pub mod types;
#[cfg(test)]
pub mod unit_tests;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
