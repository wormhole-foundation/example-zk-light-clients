use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::ConstraintSystem;
use lurk::circuit::gadgets::pointer::AllocatedPtr;
use lurk::field::LurkField;

/// Converts an `AllocatedPtr` to a `Boolean`. It assumes that the `AllocatedPtr` is a pointer to a boolean.
pub fn alloc_ptr_to_boolean<F: LurkField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    allocated_ptr: AllocatedPtr<F>,
) -> Boolean {
    Boolean::Is(
        AllocatedBit::alloc(
            &mut cs.namespace(|| "allocated_ptr to boolean"),
            Some(allocated_ptr.hash().get_value().unwrap_or(F::ZERO) == F::ONE),
        )
        .expect("alloc_ptr_to_boolean AllocatedBit::alloc panic"),
    )
}

/// Converts a `Vec<AllocatedPtr>` to a `Vec<Boolean>`. It assumes that the `AllocatedPtr` is a pointer to a boolean.
pub fn vec_to_boolean<F: LurkField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    vec: Vec<AllocatedPtr<F>>,
) -> Vec<Boolean> {
    vec.into_iter()
        .enumerate()
        .map(|(i, allocated_ptr)| {
            alloc_ptr_to_boolean(
                &mut cs.namespace(|| format!("vec_to_boolean element {i}")),
                allocated_ptr,
            )
        })
        .collect()
}

/// Extracts slices from a vector of data based on the provided ranges.
pub fn extract_slices<T: Clone>(data: &Vec<T>, ranges: &[(usize, usize)]) -> Vec<Vec<T>> {
    ranges
        .iter()
        .map(|&(offset, length)| data[offset..offset + length].to_vec())
        .collect()
}
