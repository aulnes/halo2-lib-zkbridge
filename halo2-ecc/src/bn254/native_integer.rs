//! Canonical integer comparisons for native field elements.
//!
//! A field equality alone only fixes a limb decomposition modulo the native
//! modulus. We also enforce that the represented integer is strictly below the
//! modulus, so values close to the modulus cannot be replaced with `x + p`.

use crate::bigint::{big_less_than, FixedOverflowInteger, ProperUint};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{decompose_biguint, fe_to_biguint, modulus, BigPrimeField},
    AssignedValue, Context,
};

pub(crate) const LIMB_BITS: usize = 64;

pub(crate) fn canonical_uint<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    value: AssignedValue<F>,
) -> ProperUint<F> {
    let num_limbs = (F::NUM_BITS as usize + LIMB_BITS - 1) / LIMB_BITS;
    // big_less_than also compares a limb plus a borrow (65 bits). These
    // configuration checks are independent of the witness values.
    assert!(range.lookup_bits() > 0);
    let padded_bits = (LIMB_BITS + range.lookup_bits()) / range.lookup_bits() * range.lookup_bits();
    assert!(padded_bits + range.lookup_bits() <= F::CAPACITY as usize);
    // The library's decompose_le uses a u64 mask that requires limb_bits < 64.
    // Generate 64-bit witnesses through its bigint helper instead, then bind
    // and range check every limb explicitly.
    let limbs = decompose_biguint::<F>(&fe_to_biguint(value.value()), num_limbs, LIMB_BITS)
        .into_iter()
        .map(|limb| ctx.load_witness(limb))
        .collect::<Vec<_>>();
    for &limb in &limbs {
        range.range_check(ctx, limb, LIMB_BITS);
    }
    let reconstructed = range.limbs_to_num(ctx, &limbs, LIMB_BITS);
    ctx.constrain_equal(&reconstructed, &value);
    let result = ProperUint(limbs);
    assert_canonical(ctx, range, &result);
    result
}

/// The limbs must already be range checked to `LIMB_BITS` bits each.
pub(crate) fn assert_canonical<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    value: &ProperUint<F>,
) {
    let bound = FixedOverflowInteger::from_native(&modulus::<F>(), value.limbs().len(), LIMB_BITS)
        .assign(ctx);
    let canonical = big_less_than::assign(
        range,
        ctx,
        value.clone(),
        bound,
        LIMB_BITS,
        range.gate().pow_of_two()[LIMB_BITS],
    );
    range.gate().assert_is_const(ctx, &canonical, &F::ONE);
}

/// Compares integers whose canonical decompositions have already been checked.
pub(crate) fn less_than_or_equal<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    a: &ProperUint<F>,
    b: &ProperUint<F>,
) -> AssignedValue<F> {
    let greater = big_less_than::assign(
        range,
        ctx,
        b.clone(),
        a.clone(),
        LIMB_BITS,
        range.gate().pow_of_two()[LIMB_BITS],
    );
    range.gate().not(ctx, greater)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::{
        halo2_proofs::halo2curves::{bn256::Fr, ff::Field},
        utils::{decompose_biguint, testing::base_test},
    };

    #[test]
    fn benchmark_regression_native_integer_rejects_modulus_alias() {
        // Both 0 and p reconstruct to the native value 0. Only the former is
        // a canonical integer representation. Test malicious limb witnesses
        // directly, since the honest decomposition generator never emits p.
        for alias in [false, true] {
            base_test().k(10).lookup_bits(8).expect_satisfied(!alias).run(|ctx, range| {
                let integer = if alias { modulus::<Fr>() } else { 0u64.into() };
                let limbs = decompose_biguint::<Fr>(&integer, 4, LIMB_BITS)
                    .into_iter()
                    .map(|limb| ctx.load_witness(limb))
                    .collect::<Vec<_>>();
                for &limb in &limbs {
                    range.range_check(ctx, limb, LIMB_BITS);
                }
                let reconstructed = range.limbs_to_num(ctx, &limbs, LIMB_BITS);
                range.gate().assert_is_const(ctx, &reconstructed, &Fr::ZERO);
                assert_canonical(ctx, range, &ProperUint(limbs));
            });
        }
    }
}
