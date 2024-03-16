use bellpepper::gadgets::multipack::pack_bits;
// SPDX-License-Identifier: BUSL-1.1 OR GPL-3.0-or-later
use bellpepper_core::boolean::Boolean;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_keccak::sha3;
use bellpepper_merkle_inclusion::{create_gadget_digest_impl, traits::GadgetDigest};
use ff::{PrimeField, PrimeFieldBits};
use sha3::digest::Output;
use sha3::{Digest, Sha3_256};

create_gadget_digest_impl!(Sha3, sha3, 32, Sha3_256);

/// Computes the hash of a preimage.
pub fn hash<D: Digest>(data: &[u8]) -> Output<D> {
    let mut hasher = D::new();
    hasher.update(data);

    hasher.finalize()
}

/// Reconstructs a hash from a list of field elements.
pub fn hash_fields_to_bools<F: PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    elements: &[AllocatedNum<F>],
    bit_size: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    // Compute the bit sizes of the field elements
    let mut scalar_bit_sizes = vec![F::CAPACITY as usize; bit_size / F::CAPACITY as usize];
    // If the bit size is not a multiple of 253, we need to add the remaining bits
    if bit_size % F::CAPACITY as usize != 0 {
        scalar_bit_sizes.push(bit_size % F::CAPACITY as usize)
    }

    assert_eq!(
        elements.len(),
        scalar_bit_sizes.len(),
        "Got {} elements to reconstruct hash, expected {}",
        elements.len(),
        scalar_bit_sizes.len()
    );

    let mut result: Vec<Boolean> = vec![];

    // For each field element, take the first `bit_size` bits
    for (i, bit_to_take) in scalar_bit_sizes.iter().enumerate() {
        let element =
            elements[i].to_bits_le(&mut cs.namespace(|| format!("hash field elt {i} to bits")))?;

        result.extend(element.into_iter().take(*bit_to_take));
    }

    Ok(result)
}

pub fn hash_bools_to_fields<F: PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    bits: &[Boolean],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut fields = vec![];

    for (i, chunk) in bits.chunks(F::CAPACITY as usize).enumerate() {
        fields.push(pack_bits(
            &mut cs.namespace(|| format!("pack_bits chunk {i}")),
            chunk,
        )?);
    }

    Ok(fields)
}
