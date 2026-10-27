//! Shared coordinate-tag convention for the prototype components.
//!
//! For a canonical BN254 base-field coordinate `x` in `[0, q)`, its tag in
//! the native circuit field `F` is the integer `x mod modulus(F)`. In the
//! BN254 scalar field this is `x mod r`. MSP applies this to G1 `x` or G2
//! `x.c0`; eligibility applies it to G2 `x.c0` for signatures and messages.
//! This projection is deliberately not an injective point encoding and does
//! not establish curve membership, subgroup membership, or signature validity.

use super::FpChip;
use crate::bigint::ProperCrtUint;
use crate::halo2_proofs::halo2curves::bn256::Fq;
use halo2_base::{
    utils::{biguint_to_fe, fe_to_biguint, modulus, BigPrimeField},
    AssignedValue, Context,
};

/// Reduces the canonical integer representative of a native Fq coordinate.
/// Values below the native modulus retain their previous tag unchanged.
/// Unlike canonical-byte parsing into F, this is defined for every Fq value.
pub fn native_coordinate_tag<F: BigPrimeField>(coordinate: &Fq) -> F {
    biguint_to_fe(&(fe_to_biguint(coordinate) % modulus::<F>()))
}

/// Projects an already assigned Fq coordinate without allocating a new witness.
///
/// `coordinate` must be a proper CRT representation using this chip's limb
/// configuration: its limbs are range checked and its native cell is already
/// constrained to their reconstruction modulo F. This function additionally
/// requires the represented integer to be below q, ensuring it is the canonical
/// Fq representative, and returns that same constrained native cell.
pub fn assigned_coordinate_tag<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F>,
    coordinate: &ProperCrtUint<F>,
) -> AssignedValue<F> {
    assert_eq!(coordinate.limbs().len(), fp_chip.num_limbs, "coordinate limb configuration");
    fp_chip.enforce_less_than_p(ctx, coordinate.clone());
    *coordinate.native()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint::ProperUint, fields::FieldChip};
    use halo2_base::{
        gates::{GateInstructions, RangeInstructions},
        halo2_proofs::halo2curves::{bn256::Fr, ff::Field},
        utils::{decompose_biguint, testing::base_test, ScalarField},
    };

    #[test]
    fn benchmark_regression_coordinate_tag_boundaries() {
        let r = modulus::<Fr>();
        let q = modulus::<Fq>();
        let cases = [
            (0u64.into(), Fr::ZERO),
            (&r - 1u64, -Fr::ONE),
            (r.clone(), Fr::ZERO),
            (&r + 1u64, Fr::ONE),
            (&q - 1u64, biguint_to_fe::<Fr>(&(&q - &r - 1u64))),
        ];
        base_test().k(10).lookup_bits(8).run(|ctx, range| {
            let fp = FpChip::<Fr>::new(range, 90, 3);
            for (integer, expected) in cases {
                let coordinate = biguint_to_fe::<Fq>(&integer);
                let native_tag = native_coordinate_tag::<Fr>(&coordinate);
                assert_eq!(native_tag, expected);
                if integer < r {
                    assert_eq!(native_tag, Fr::from_bytes_le(&coordinate.to_bytes()));
                }
                let assigned = fp.load_private(ctx, coordinate);
                let tag = assigned_coordinate_tag(ctx, &fp, &assigned);
                range.gate().assert_is_const(ctx, &tag, &expected);
                assert_eq!(tag.cell, assigned.native().cell, "projection must reuse the CRT cell");
            }
        });
    }

    #[test]
    fn benchmark_regression_coordinate_tag_rejects_noncanonical_fq() {
        let q = modulus::<Fq>();
        for integer in [&q - 1u64, q.clone(), &q + 1u64] {
            let canonical = integer < q;
            base_test().k(10).lookup_bits(8).expect_satisfied(canonical).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                // Assign raw integer limbs to test malicious representatives
                // which cannot be constructed as canonical native Fq values.
                let limbs = ctx.assign_witnesses(decompose_biguint::<Fr>(&integer, 3, 90));
                for &limb in &limbs {
                    range.range_check(ctx, limb, 90);
                }
                let coordinate = ProperUint(limbs).into_crt(
                    ctx,
                    range.gate(),
                    integer.clone(),
                    &fp.limb_bases,
                    90,
                );
                assigned_coordinate_tag(ctx, &fp, &coordinate);
            });
        }
    }

    #[test]
    fn benchmark_regression_coordinate_tag_native_cell_binding() {
        base_test().k(10).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
            let fp = FpChip::<Fr>::new(range, 90, 3);
            let value = biguint_to_fe::<Fq>(&(modulus::<Fr>() + 1u64));
            let coordinate = fp.load_private(ctx, value);
            let tag = assigned_coordinate_tag(ctx, &fp, &coordinate);
            // Do not assert the expected tag here: rejection must come from
            // its CRT reconstruction link, not an extra equality to one.
            tag.debug_prank(ctx, Fr::from(2));
        });
    }
}
