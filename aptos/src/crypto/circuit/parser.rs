// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::{PrimeFieldBits};

fn bits_to_u64(bits: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, &bit) in bits.iter().enumerate() {
        if bit == 1 {
            value |= 1 << i;
        }
    }
    value
}

pub fn extract_vec<F: PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    slice: &[AllocatedNum<F>],
    offset: AllocatedNum<F>,
    length: AllocatedNum<F>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let offset_value = bits_to_u64(
        &offset
            .to_bits_le_strict(cs.namespace(|| "offset_to_bits"))?
            .iter()
            .map(|b| if b.get_value().unwrap_or(false) { 1 } else { 0 })
            .collect::<Vec<_>>(),
    );
    let length_value = bits_to_u64(
        &length
            .to_bits_le_strict(cs.namespace(|| "length_to_bits"))?
            .iter()
            .map(|b| if b.get_value().unwrap_or(false) { 1 } else { 0 })
            .collect::<Vec<_>>(),
    );

    let mut nbr_elements = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(F::ZERO))?;
    let alloc_one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::ONE))?;
    let mut bytes_payload = (0..length_value)
        .map(|i| {
            AllocatedNum::alloc(&mut cs.namespace(|| format!("byte {i} init")), || {
                Ok(F::ZERO)
            })
            .unwrap()
        })
        .collect::<Vec<_>>();

    for (payload_idx, slice_idx) in (offset_value..offset_value + length_value).enumerate() {
        bytes_payload[payload_idx] = slice[slice_idx as usize].clone();
        nbr_elements = nbr_elements.add(
            &mut cs.namespace(|| format!("bytes_pointer_increment {payload_idx}")),
            &alloc_one,
        )?;
    }

    cs.enforce(
        || "nbr_elements equal to length",
        |lc| lc + nbr_elements.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + length.get_variable(),
    );

    Ok(bytes_payload)
}

#[cfg(test)]
mod test {
    use arecibo::traits::Engine;
    use super::*;
    use crate::crypto::circuit::E1;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use serde::{Deserialize, Serialize};

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
        let string_offset = AllocatedNum::alloc(&mut cs.namespace(|| "string_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(1))
        })
        .unwrap();

        // Length 5
        let string_length = AllocatedNum::alloc(&mut cs.namespace(|| "string_length"), || {
            Ok(<E1 as Engine>::Scalar::from(5))
        })
        .unwrap();

        let alloc_bytes = extract_vec(
            &mut cs.namespace(|| "extract_string"),
            &data_bytes_allocated,
            string_offset,
            string_length,
        )
        .unwrap();

        for (i, alloc_byte) in alloc_bytes.iter().enumerate() {
            assert_eq!(alloc_byte.get_value().unwrap(), string_bytes_num[i])
        }

        /*******************************************
         * Extract the number from the data
         *******************************************/
        // Offset is str.len() + 1
        let number_offset = AllocatedNum::alloc(&mut cs.namespace(|| "number_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(6))
        })
        .unwrap();
        // Length 8 because u64
        let number_length = AllocatedNum::alloc(&mut cs.namespace(|| "number_length"), || {
            Ok(<E1 as Engine>::Scalar::from(8))
        })
        .unwrap();

        let alloc_bytes = extract_vec(
            &mut cs.namespace(|| "extract_number"),
            &data_bytes_allocated,
            number_offset,
            number_length,
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
        let vec_offset = AllocatedNum::alloc(&mut cs.namespace(|| "vec_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(15))
        })
        .unwrap();
        // Length nbr_elements * 8
        let vec_length = AllocatedNum::alloc(&mut cs.namespace(|| "vec_length"), || {
            Ok(<E1 as Engine>::Scalar::from(5 * 8))
        })
        .unwrap();

        let alloc_bytes = extract_vec(
            &mut cs.namespace(|| "extract_vec"),
            &data_bytes_allocated,
            vec_offset,
            vec_length,
        )
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

        let mut aptos_wrapper = AptosWrapper::new(4, 1);

        aptos_wrapper.generate_traffic();

        let mut cs = TestConstraintSystem::<<E1 as Engine>::Scalar>::new();

        let intern_li_alloc = aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .enumerate().map(|(i,b)| AllocatedNum::alloc(&mut cs.namespace(|| format!("ledger_info_byte {i}")), || Ok(<E1 as Engine>::Scalar::from(*b as u64))).unwrap()).collect::<Vec<_>>();

        let ledger_info_bytes_alloc = bcs::to_bytes(&aptos_wrapper.get_latest_li().unwrap().ledger_info())
            .unwrap()
            .iter()
            .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
            .collect::<Vec<_>>();

        let ledger_info_len: u64 = 8 // epoch
            + 8 // round
            + 32 // id
            + 32 // executed state id
            + 8 // version
            + 8 // timestamp
            + 1 // None variant for new epoch state
            + 32; // consensus data hash
        let offset_signature = ledger_info_len + 1; // next byte
        let signature_len = intern_li_alloc.len() as u64 - offset_signature;
        let offset_ledger_info = 1; // not taking the variant byte

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let offset_ledger_info_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "ledger_info_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(offset_ledger_info))
        }).unwrap();
        let ledger_info_len_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "ledger_info_len"), || {
            Ok(<E1 as Engine>::Scalar::from(ledger_info_len))
        }).unwrap();

        let ledger_info_bytes_payload = extract_vec(
            &mut cs.namespace(|| "extract_ledger_info"),
            &intern_li_alloc,
            offset_ledger_info_alloc,
            ledger_info_len_alloc,
        )
            .unwrap();

        assert_eq!(ledger_info_bytes_payload.len(), ledger_info_bytes_alloc.len());
        for (i, ledger_info_byte) in ledger_info_bytes_alloc.iter().enumerate() {
            assert_eq!(&ledger_info_bytes_payload[i].get_value().unwrap(), ledger_info_byte)
        }

        assert!(cs.is_satisfied());

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let offset_signature_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "signature_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(offset_signature))
        }).unwrap();
        let signature_len_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "signature_len"), || {
            Ok(<E1 as Engine>::Scalar::from(signature_len))
        }).unwrap();

        let aggregated_sig_bytes_payload = extract_vec(
            &mut cs.namespace(|| "extract_aggregated_sig"),
            &intern_li_alloc,
            offset_signature_alloc,
            signature_len_alloc,
        )
            .unwrap();

        assert_eq!(aggregated_sig_bytes_payload.len() + ledger_info_bytes_payload.len() + 1usize, intern_li_alloc.len());

        /*******************************************
         * Over testing to ensure proper parsing
         *******************************************/
        let reconstructed_bytes = vec![vec![AllocatedNum::alloc(&mut cs.namespace(|| "byte_0"), || Ok(<E1 as Engine>::Scalar::from(0))).unwrap()], ledger_info_bytes_payload, aggregated_sig_bytes_payload].concat();

        for (i, byte) in intern_li_alloc.iter().enumerate() {
            assert_eq!(byte.get_value().unwrap(), reconstructed_bytes[i].get_value().unwrap())
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
            .enumerate().map(|(i,b)| AllocatedNum::alloc(&mut cs.namespace(|| format!("ledger_info_byte {i}")), || Ok(<E1 as Engine>::Scalar::from(*b as u64))).unwrap()).collect::<Vec<_>>();

        let ledger_info_bytes_alloc = bcs::to_bytes(&aptos_wrapper.get_latest_li().unwrap().ledger_info())
            .unwrap()
            .iter()
            .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
            .collect::<Vec<_>>();


        let validators_list_len = 1 + NBR_VALIDATORS as u64 * (32 + 49 + 8); // vec size + nbr_validators * (account address + pub key + voting power)
        let offset_validator_list = 8 // epoch
            + 8 // round
            + 32 // id
            + 32 // executed state id
            + 8 // version
            + 8 // timestamp
            + 1 // Some
            + 8 // epoch
            + 1 ; // next byte

        let ledger_info_len: u64 = 8 // epoch
            + 8 // round
            + 32 // id
            + 32 // executed state id
            + 8 // version
            + 8 // timestamp
            + 1 // Some
            + 8 // epoch
            + validators_list_len
            + 32; // consensus data hash
        let offset_signature = ledger_info_len + 1; // next byte
        let signature_len = intern_li_alloc.len() as u64 - offset_signature;
        let offset_ledger_info = 1; // not taking the variant byte


        /*******************************************
         * Extract validator list from the data
         *******************************************/
        let offset_validator_list_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "validator_list_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(offset_validator_list)) }).unwrap();
        let validator_list_len_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "validator_list_len"), || { Ok(<E1 as Engine>::Scalar::from(validators_list_len)) }).unwrap();

        let validator_list_bytes_payload = extract_vec(
            &mut cs.namespace(|| "extract_validator_list"),
            &intern_li_alloc,
            offset_validator_list_alloc,
            validator_list_len_alloc,
        ).unwrap();

        for (validator_list_byte, i) in validator_list_bytes_payload.iter().zip(offset_validator_list as usize..offset_validator_list as usize + validators_list_len as usize) {
            assert_eq!(validator_list_byte.get_value().unwrap(), intern_li_alloc[i].get_value().unwrap())
        }

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let offset_ledger_info_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "ledger_info_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(offset_ledger_info))
        }).unwrap();
        let ledger_info_len_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "ledger_info_len"), || {
            Ok(<E1 as Engine>::Scalar::from(ledger_info_len))
        }).unwrap();

        let ledger_info_bytes_payload = extract_vec(
            &mut cs.namespace(|| "extract_ledger_info"),
            &intern_li_alloc,
            offset_ledger_info_alloc,
            ledger_info_len_alloc,
        )
            .unwrap();

        assert_eq!(ledger_info_bytes_payload.len(), ledger_info_bytes_alloc.len());
        for (i, ledger_info_byte) in ledger_info_bytes_alloc.iter().enumerate() {
            assert_eq!(&ledger_info_bytes_payload[i].get_value().unwrap(), ledger_info_byte)
        }

        assert!(cs.is_satisfied());

        /*******************************************
         * Extract LedgerInfo from the data
         *******************************************/
        let offset_signature_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "signature_offset"), || {
            Ok(<E1 as Engine>::Scalar::from(offset_signature))
        }).unwrap();
        let signature_len_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "signature_len"), || {
            Ok(<E1 as Engine>::Scalar::from(signature_len))
        }).unwrap();

        let aggregated_sig_bytes_payload = extract_vec(
            &mut cs.namespace(|| "extract_aggregated_sig"),
            &intern_li_alloc,
            offset_signature_alloc,
            signature_len_alloc,
        )
            .unwrap();

        assert_eq!(aggregated_sig_bytes_payload.len() + ledger_info_bytes_payload.len() + 1usize, intern_li_alloc.len());

        /*******************************************
         * Over testing to ensure proper parsing
         *******************************************/
        let reconstructed_bytes = vec![vec![AllocatedNum::alloc(&mut cs.namespace(|| "byte_0"), || Ok(<E1 as Engine>::Scalar::from(0))).unwrap()], ledger_info_bytes_payload, aggregated_sig_bytes_payload].concat();

        for (i, byte) in intern_li_alloc.iter().enumerate() {
            assert_eq!(byte.get_value().unwrap(), reconstructed_bytes[i].get_value().unwrap())
        }
    }
}
