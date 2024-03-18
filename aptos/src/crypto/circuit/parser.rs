// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use arecibo::traits::Engine;
use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldBits};
use sha3::digest::typenum::private::IsGreaterOrEqualPrivate;

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

    let mut nbr_elements = offset.clone();
    let alloc_one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::ONE))?;
    let mut bytes_payload = (0..length_value)
        .map(|i| {
            AllocatedNum::alloc(&mut cs.namespace(|| format!("byte {i} init")), || {
                Ok(F::ZERO)
            })
            .unwrap()
        })
        .collect::<Vec<_>>();
    for (payload_idx, slice_idx) in (offset_value..length_value).enumerate() {
        bytes_payload[payload_idx] = slice[slice_idx as usize].clone();
        nbr_elements = nbr_elements.add(
            &mut cs.namespace(|| format!("bytes_pointer_increment {i}")),
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
    use super::*;
    use crate::crypto::circuit::E1;
    use crate::types::ledger_info::LedgerInfoWithSignatures;
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
        dbg!(data.string.as_bytes());
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
            dbg!(alloc_byte.get_value().unwrap());
            dbg!(string_bytes_num[i]);
            dbg!(string_bytes_num[i + 1]);
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
    fn test_ledger_info() {
        use crate::unit_tests::aptos::wrapper::AptosWrapper;

        let mut aptos_wrapper = AptosWrapper::new(4);

        aptos_wrapper.generate_traffic();

        let intern_li_alloc = &aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .map(|b| <E1 as Engine>::Scalar::from(*b as u64))
            .collect::<Vec<_>>();

        let mut cs = TestConstraintSystem::<<E1 as Engine>::Scalar>::new();
    }
}
