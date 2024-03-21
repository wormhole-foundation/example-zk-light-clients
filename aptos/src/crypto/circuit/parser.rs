// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later

use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_core::boolean::Boolean;
use ff::PrimeFieldBits;

pub fn extract_vec<
    F: PrimeFieldBits,
    CS: ConstraintSystem<F>,
    const OFFSET: usize,
    const LENGTH: usize,
>(
    _cs: &mut CS,
    slice: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut return_vec = vec![];
    for boolean in slice.iter().skip(OFFSET).take(LENGTH) {
        return_vec.push(boolean.clone());
    }

    Ok(return_vec)
}

pub type BitsPayload = (Vec<Boolean>, Vec<Boolean>, Vec<Boolean>);

pub fn handle_new_epoch<
    F: PrimeFieldBits,
    CS: ConstraintSystem<F>,
    const OFFSET_LEDGER_INFO: usize,
    const LEDGER_INFO_LEN: usize,
    const OFFSET_VALIDATORS_LIST: usize,
    const VALIDATORS_LIST_LEN: usize,
    const OFFSET_SIGNATURE: usize,
    const SIGNATURE_LEN: usize,
>(
    cs: &mut CS,
    ledger_info_w_signatures: &[Boolean],
) -> Result<BitsPayload, SynthesisError> {
    let ledger_info =
        extract_vec::<F, CS, OFFSET_LEDGER_INFO, LEDGER_INFO_LEN>(cs, ledger_info_w_signatures)?;
    let validators_list = extract_vec::<F, CS, OFFSET_VALIDATORS_LIST, VALIDATORS_LIST_LEN>(
        cs,
        ledger_info_w_signatures,
    )?;
    let signature =
        extract_vec::<F, CS, OFFSET_SIGNATURE, SIGNATURE_LEN>(cs, ledger_info_w_signatures)?;

    Ok((ledger_info, validators_list, signature))
}

#[cfg(test)]
mod test {
    use arecibo::traits::Engine;
    use bellpepper_core::boolean::field_into_boolean_vec_le;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use serde::{Deserialize, Serialize};

    use crate::crypto::circuit::E1;

    use super::*;

    fn compare_list_bools(slice_1: &[Boolean], slice_2: &[Boolean]) {
        for (elt_1, elt_2) in slice_1.iter().zip(slice_2.iter()) {
            assert_eq!(elt_1.get_value().unwrap(), elt_2.get_value().unwrap())
        }
    }

    #[test]
    fn test_extract_mock_data() {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct TargetData {
            string: String,
            number: u64,
            vec: Vec<u64>,
        }

        // Test constraint system
        let mut cs = TestConstraintSystem::<<E1 as Engine>::Scalar>::new();

        let data = TargetData {
            string: "hello".to_string(),
            number: 42,
            vec: vec![1, 2, 3, 4, 5],
        };

        let string_le_bits = data
            .string
            .as_bytes()
            .iter()
            .enumerate()
            .flat_map(|(i, b)| {
                field_into_boolean_vec_le(
                    &mut cs.namespace(|| format!("string byte to bit {i}")),
                    Some(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
                .into_iter()
                .take(8)
            })
            .collect::<Vec<_>>();

        let number_le_bits = bcs::to_bytes(&data.number)
            .unwrap()
            .iter()
            .enumerate()
            .flat_map(|(i, b)| {
                field_into_boolean_vec_le(
                    &mut cs.namespace(|| format!("number byte to bit {i}")),
                    Some(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
                .into_iter()
                .take(8)
            })
            .collect::<Vec<_>>();
        let vec_le_bits = bcs::to_bytes(&data.vec)
            .unwrap()
            .iter()
            .enumerate()
            .flat_map(|(i, b)| {
                field_into_boolean_vec_le(
                    &mut cs.namespace(|| format!("vec byte to bit {i}")),
                    Some(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
                .into_iter()
                .take(8)
            })
            .collect::<Vec<_>>();
        let data_boolean = bcs::to_bytes(&data)
            .unwrap()
            .iter()
            .enumerate()
            .flat_map(|(i, b)| {
                field_into_boolean_vec_le(
                    &mut cs.namespace(|| format!("byte to bit {i}")),
                    Some(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
                .into_iter()
                .take(8)
            })
            .collect::<Vec<Boolean>>();

        /*******************************************
         * Extract the string from the data
         *******************************************/
        // Offset is 8 as 0 is its length
        // Length 40 bits
        let booleans =
            extract_vec::<_, _, 8, 40>(&mut cs.namespace(|| "extract_string"), &data_boolean)
                .unwrap();

        compare_list_bools(&booleans, &string_le_bits);

        /*******************************************
         * Extract the number from the data
         *******************************************/
        // Offset is str.len() + 1
        // Length 64 bits
        let booleans =
            extract_vec::<_, _, 48, 64>(&mut cs.namespace(|| "extract_number"), &data_boolean)
                .unwrap();

        compare_list_bools(&booleans, &number_le_bits);

        /*******************************************
         * Extract the vector from the data
         *******************************************/
        // Offset is offset_str + str.len()
        // Length nbr_elements * 8 * 8
        let booleans =
            extract_vec::<_, _, 112, 320>(&mut cs.namespace(|| "extract_vec"), &data_boolean)
                .unwrap();

        compare_list_bools(&booleans, &vec_le_bits);
        assert!(cs.is_satisfied());
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_extract_with_no_new_epoch() {
        use crate::unit_tests::aptos::wrapper::AptosWrapper;

        const NBR_VALIDATORS: usize = 1;
        let mut aptos_wrapper = AptosWrapper::new(4, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();

        let mut cs = TestConstraintSystem::<<E1 as Engine>::Scalar>::new();

        let intern_li_le_bits = aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .enumerate()
            .flat_map(|(i, b)| {
                field_into_boolean_vec_le(
                    &mut cs.namespace(|| format!("intern li byte to bit {i}")),
                    Some(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
                .into_iter()
                .take(8)
            })
            .collect::<Vec<Boolean>>();

        let ledger_info_le_bits =
            bcs::to_bytes(&aptos_wrapper.get_latest_li().unwrap().ledger_info())
                .unwrap()
                .iter()
                .enumerate()
                .flat_map(|(i, b)| {
                    field_into_boolean_vec_le(
                        &mut cs.namespace(|| format!("ledger info byte to bit {i}")),
                        Some(<E1 as Engine>::Scalar::from(*b as u64)),
                    )
                    .unwrap()
                    .into_iter()
                    .take(8)
                })
                .collect::<Vec<_>>();

        const LEDGER_INFO_LEN: usize = 8 // epoch
            + 8 // round
            + 32 // id
            + 32 // executed state id
            + 8 // version
            + 8 // timestamp
            + 1 // None variant for new epoch state
            + 32; // consensus data hash

        const OFFSET_SIGNATURE: usize = LEDGER_INFO_LEN + 1; // next byte
        const SIGNATURE_LEN: usize = 1 + (NBR_VALIDATORS + 7) / 8 + 1 + 1 + 96; // signature_len + (NBR_VALIDATORS) + 7 / 8 + some_sig + sig_len + sig_nbr_bytes
        const OFFSET_LEDGER_INFO: usize = 1; // not taking the variant byte

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let ledger_info_le_bits_payload =
            extract_vec::<_, _, { OFFSET_LEDGER_INFO * 8 }, { LEDGER_INFO_LEN * 8 }>(
                &mut cs.namespace(|| "extract_ledger_info"),
                &intern_li_le_bits,
            )
            .unwrap();

        assert_eq!(ledger_info_le_bits_payload.len(), ledger_info_le_bits.len());

        compare_list_bools(&ledger_info_le_bits_payload, &ledger_info_le_bits);

        assert!(cs.is_satisfied());

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let aggregated_sig_le_bits_payload =
            extract_vec::<_, _, { OFFSET_SIGNATURE * 8 }, { SIGNATURE_LEN * 8 }>(
                &mut cs.namespace(|| "extract_aggregated_sig"),
                &intern_li_le_bits,
            )
            .unwrap();

        assert_eq!(
            aggregated_sig_le_bits_payload.len() + ledger_info_le_bits_payload.len() + 8usize,
            intern_li_le_bits.len()
        );

        /*******************************************
         * Over testing to ensure proper parsing
         *******************************************/
        let reconstructed_le_bits = vec![
            (0..8).map(|_| Boolean::Constant(false)).collect::<Vec<_>>(),
            ledger_info_le_bits_payload,
            aggregated_sig_le_bits_payload,
        ]
        .concat();

        compare_list_bools(&reconstructed_le_bits, &intern_li_le_bits);
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_extract_with_new_epoch() {
        use crate::unit_tests::aptos::wrapper::AptosWrapper;

        const NBR_VALIDATORS: usize = 15;

        let mut aptos_wrapper = AptosWrapper::new(4, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let mut cs = TestConstraintSystem::<<E1 as Engine>::Scalar>::new();

        let intern_li_le_bits = aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .enumerate()
            .flat_map(|(i, b)| {
                field_into_boolean_vec_le(
                    &mut cs.namespace(|| format!("intern li byte to bit {i}")),
                    Some(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
                .into_iter()
                .take(8)
            })
            .collect::<Vec<_>>();

        let ledger_info_le_bits =
            bcs::to_bytes(&aptos_wrapper.get_latest_li().unwrap().ledger_info())
                .unwrap()
                .iter()
                .enumerate()
                .flat_map(|(i, b)| {
                    field_into_boolean_vec_le(
                        &mut cs.namespace(|| format!("ledger info byte to bit {i}")),
                        Some(<E1 as Engine>::Scalar::from(*b as u64)),
                    )
                    .unwrap()
                    .into_iter()
                    .take(8)
                })
                .collect::<Vec<_>>();

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
        const OFFSET_LEDGER_INFO: usize = 1; // not taking the variant byte

        /*******************************************
         * Extract validator list from the data
         *******************************************/
        let validator_list_le_bits_payload =
            extract_vec::<_, _, { OFFSET_VALIDATOR_LIST * 8 }, { VALIDATORS_LIST_LEN * 8 }>(
                &mut cs.namespace(|| "extract_validator_list"),
                &intern_li_le_bits,
            )
            .unwrap();

        for (validator_list_bit, i) in validator_list_le_bits_payload
            .iter()
            .zip(OFFSET_VALIDATOR_LIST * 8..(OFFSET_VALIDATOR_LIST + VALIDATORS_LIST_LEN) * 8)
        {
            assert_eq!(
                validator_list_bit.get_value().unwrap(),
                intern_li_le_bits[i].get_value().unwrap()
            )
        }

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let ledger_info_le_bits_payload =
            extract_vec::<_, _, { OFFSET_LEDGER_INFO * 8 }, { LEDGER_INFO_LEN * 8 }>(
                &mut cs.namespace(|| "extract_ledger_info"),
                &intern_li_le_bits,
            )
            .unwrap();

        assert_eq!(ledger_info_le_bits_payload.len(), ledger_info_le_bits.len());
        compare_list_bools(&ledger_info_le_bits_payload, &ledger_info_le_bits);

        assert!(cs.is_satisfied());

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let aggregated_sig_le_bits_payload =
            extract_vec::<_, _, { OFFSET_SIGNATURE * 8 }, { SIGNATURE_LEN * 8 }>(
                &mut cs.namespace(|| "extract_aggregated_sig"),
                &intern_li_le_bits,
            )
            .unwrap();

        assert_eq!(
            aggregated_sig_le_bits_payload.len() + ledger_info_le_bits_payload.len() + 8usize,
            intern_li_le_bits.len()
        );

        /*******************************************
         * Test handle_new_epoch
         *******************************************/
        let (ledger_info, validators_list, signature) = handle_new_epoch::<
            _,
            _,
            { OFFSET_LEDGER_INFO * 8 },
            { LEDGER_INFO_LEN * 8 },
            { OFFSET_VALIDATOR_LIST * 8 },
            { VALIDATORS_LIST_LEN * 8 },
            { OFFSET_SIGNATURE * 8 },
            { SIGNATURE_LEN * 8 },
        >(&mut cs, &intern_li_le_bits)
        .unwrap();

        compare_list_bools(&ledger_info, &ledger_info_le_bits_payload);
        compare_list_bools(&validators_list, &validator_list_le_bits_payload);
        compare_list_bools(&signature, &aggregated_sig_le_bits_payload);

        /*******************************************
         * Over testing to ensure proper parsing
         *******************************************/
        let reconstructed_le_bits = vec![
            (0..8).map(|_| Boolean::Constant(false)).collect::<Vec<_>>(),
            ledger_info,
            signature,
        ]
        .concat();

        for (i, byte) in intern_li_le_bits.iter().enumerate() {
            assert_eq!(
                byte.get_value().unwrap(),
                reconstructed_le_bits[i].get_value().unwrap()
            )
        }
    }
}
