use bellpepper_core::{ConstraintSystem, SynthesisError};
// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use bellpepper_core::num::AllocatedNum;
use ff::PrimeFieldBits;

fn bits_to_u64(bits: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, &bit) in bits.iter().enumerate() {
        if bit == 1 {
            value |= 1 << i;
        }
    }
    value
}

pub fn extract_vec<
    F: PrimeFieldBits,
    CS: ConstraintSystem<F>,
    const OFFSET: usize,
    const LENGTH: usize,
>(
    _cs: &mut CS,
    slice: &[AllocatedNum<F>],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut bytes_payload = vec![];
    for i in OFFSET..OFFSET + LENGTH {
        bytes_payload.push(slice[i].clone());
    }

    Ok(bytes_payload)
}

#[cfg(test)]
mod test {
    use arecibo::traits::Engine;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use serde::{Deserialize, Serialize};

    use crate::crypto::circuit::E1;

    use super::*;

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

        let string_bytes_num = data
            .string
            .as_bytes()
            .iter()
            .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
            .collect::<Vec<_>>();

        let number_bytes_num = bcs::to_bytes(&data.number)
            .unwrap()
            .iter()
            .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
            .collect::<Vec<_>>();
        let vec_bytes_num = bcs::to_bytes(&data.vec)
            .unwrap()
            .iter()
            .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
            .collect::<Vec<_>>();
        let data_bytes_allocated = bcs::to_bytes(&data)
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedNum::alloc(
                    &mut cs.namespace(|| format!("data_bytes_allocated_{}", i)),
                    || Ok(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        /*******************************************
         * Extract the string from the data
         *******************************************/
        // Offset is 1 as 0 is its length
        // Length 5
        let alloc_bytes = extract_vec::<_, _, 1, 5>(
            &mut cs.namespace(|| "extract_string"),
            &data_bytes_allocated,
        )
        .unwrap();

        for (i, alloc_byte) in alloc_bytes.iter().enumerate() {
            assert_eq!(alloc_byte.get_value().unwrap(), string_bytes_num[i])
        }

        /*******************************************
         * Extract the number from the data
         *******************************************/
        // Offset is str.len() + 1
        // Length 8 because u64
        let alloc_bytes = extract_vec::<_, _, 6, 8>(
            &mut cs.namespace(|| "extract_number"),
            &data_bytes_allocated,
        )
        .unwrap();

        for (i, alloc_byte) in alloc_bytes.iter().enumerate() {
            // We jump the size value
            assert_eq!(alloc_byte.get_value().unwrap(), number_bytes_num[i])
        }

        /*******************************************
         * Extract the vector from the data
         *******************************************/
        // Offset is str.len() + 1 + number.len() + 1 (size of vec)
        // Length nbr_elements * 8
        let alloc_bytes =
            extract_vec::<_, _, 15, 40>(&mut cs.namespace(|| "extract_vec"), &data_bytes_allocated)
                .unwrap();

        for (i, alloc_byte) in alloc_bytes.iter().enumerate() {
            // We jump the size value
            assert_eq!(alloc_byte.get_value().unwrap(), vec_bytes_num[i + 1])
        }

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

        let intern_li_alloc = aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedNum::alloc(
                    &mut cs.namespace(|| format!("ledger_info_byte {i}")),
                    || Ok(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let ledger_info_bytes_alloc =
            bcs::to_bytes(&aptos_wrapper.get_latest_li().unwrap().ledger_info())
                .unwrap()
                .iter()
                .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
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
        let ledger_info_bytes_payload = extract_vec::<_, _, OFFSET_LEDGER_INFO, LEDGER_INFO_LEN>(
            &mut cs.namespace(|| "extract_ledger_info"),
            &intern_li_alloc,
        )
        .unwrap();

        assert_eq!(
            ledger_info_bytes_payload.len(),
            ledger_info_bytes_alloc.len()
        );
        for (i, ledger_info_byte) in ledger_info_bytes_alloc.iter().enumerate() {
            assert_eq!(
                &ledger_info_bytes_payload[i].get_value().unwrap(),
                ledger_info_byte
            )
        }

        assert!(cs.is_satisfied());

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let aggregated_sig_bytes_payload = extract_vec::<_, _, OFFSET_SIGNATURE, SIGNATURE_LEN>(
            &mut cs.namespace(|| "extract_aggregated_sig"),
            &intern_li_alloc,
        )
        .unwrap();

        assert_eq!(
            aggregated_sig_bytes_payload.len() + ledger_info_bytes_payload.len() + 1usize,
            intern_li_alloc.len()
        );

        /*******************************************
         * Over testing to ensure proper parsing
         *******************************************/
        let reconstructed_bytes = vec![
            vec![AllocatedNum::alloc(&mut cs.namespace(|| "byte_0"), || {
                Ok(<E1 as Engine>::Scalar::from(0))
            })
            .unwrap()],
            ledger_info_bytes_payload,
            aggregated_sig_bytes_payload,
        ]
        .concat();

        for (i, byte) in intern_li_alloc.iter().enumerate() {
            assert_eq!(
                byte.get_value().unwrap(),
                reconstructed_bytes[i].get_value().unwrap()
            )
        }
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

        let intern_li_alloc = aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedNum::alloc(
                    &mut cs.namespace(|| format!("ledger_info_byte {i}")),
                    || Ok(<E1 as Engine>::Scalar::from(*b as u64)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let ledger_info_bytes_alloc =
            bcs::to_bytes(&aptos_wrapper.get_latest_li().unwrap().ledger_info())
                .unwrap()
                .iter()
                .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
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
        let validator_list_bytes_payload =
            extract_vec::<_, _, OFFSET_VALIDATOR_LIST, VALIDATORS_LIST_LEN>(
                &mut cs.namespace(|| "extract_validator_list"),
                &intern_li_alloc,
            )
            .unwrap();

        for (validator_list_byte, i) in validator_list_bytes_payload
            .iter()
            .zip(OFFSET_VALIDATOR_LIST..OFFSET_VALIDATOR_LIST + VALIDATORS_LIST_LEN)
        {
            assert_eq!(
                validator_list_byte.get_value().unwrap(),
                intern_li_alloc[i].get_value().unwrap()
            )
        }

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let ledger_info_bytes_payload = extract_vec::<_, _, OFFSET_LEDGER_INFO, LEDGER_INFO_LEN>(
            &mut cs.namespace(|| "extract_ledger_info"),
            &intern_li_alloc,
        )
        .unwrap();

        assert_eq!(
            ledger_info_bytes_payload.len(),
            ledger_info_bytes_alloc.len()
        );
        for (i, ledger_info_byte) in ledger_info_bytes_alloc.iter().enumerate() {
            assert_eq!(
                &ledger_info_bytes_payload[i].get_value().unwrap(),
                ledger_info_byte
            )
        }

        assert!(cs.is_satisfied());

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let aggregated_sig_bytes_payload = extract_vec::<_, _, OFFSET_SIGNATURE, SIGNATURE_LEN>(
            &mut cs.namespace(|| "extract_aggregated_sig"),
            &intern_li_alloc,
        )
        .unwrap();

        assert_eq!(
            aggregated_sig_bytes_payload.len() + ledger_info_bytes_payload.len() + 1usize,
            intern_li_alloc.len()
        );

        /*******************************************
         * Over testing to ensure proper parsing
         *******************************************/
        let reconstructed_bytes = vec![
            vec![AllocatedNum::alloc(&mut cs.namespace(|| "byte_0"), || {
                Ok(<E1 as Engine>::Scalar::from(0))
            })
            .unwrap()],
            ledger_info_bytes_payload,
            aggregated_sig_bytes_payload,
        ]
        .concat();

        for (i, byte) in intern_li_alloc.iter().enumerate() {
            assert_eq!(
                byte.get_value().unwrap(),
                reconstructed_bytes[i].get_value().unwrap()
            )
        }
    }
}
