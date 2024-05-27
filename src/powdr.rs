#![allow(unsafe_code)]

use powdr_riscv_runtime::arith::affine_256_modmul;
use crate::{Encoding, U256};

/// Modular multiplication of two 256-bit Uint values using the RISC Zero accelerator.
/// Returns a result in the equivelence class of integers under the modulus, but the result is not
/// guarenteed to be fully reduced. In particular, it may include any number of multiples of the
/// modulus.
#[inline(always)]
pub fn modmul_u256_denormalized(a: &U256, b: &U256, modulus: &U256) -> U256 {
    U256::from_le_bytes(unsafe {
        affine_256_modmul(
            a.as_ptr(),
            b.as_ptr(),
            modulus.as_ptr(),
        ).1 // the remainder
    })
}