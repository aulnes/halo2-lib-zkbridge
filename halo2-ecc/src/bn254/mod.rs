use crate::bigint::ProperCrtUint;
use crate::fields::vector::FieldVector;
use crate::fields::{fp, fp12, fp2};
use crate::halo2_proofs::halo2curves::bn256::{Fq, Fq12, Fq2};
use halo2_base::utils::BigPrimeField;

pub mod bls_signature;
pub mod bls_signature_inverse;
pub mod final_exp;
pub mod pairing;
pub mod merkle_tree;
pub mod combine_bls_mt;
pub mod shuffle;
pub mod msp;
pub mod shuffle2;

#[derive(Clone)]
pub struct MerkleInfo<F: BigPrimeField>{
    pub leaf: F,
    pub path: Vec<F>,
    pub index: Vec<bool>, // true: left, false: right
}


pub type FpChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type FpPoint<F> = ProperCrtUint<F>;
pub type FqPoint<F> = FieldVector<FpPoint<F>>;
pub type Fp2Chip<'chip, F> = fp2::Fp2Chip<'chip, F, FpChip<'chip, F>, Fq2>;
pub type Fp12Chip<'chip, F> = fp12::Fp12Chip<'chip, F, FpChip<'chip, F>, Fq12, 9>;

#[cfg(test)]
pub(crate) mod tests;
