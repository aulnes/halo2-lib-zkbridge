//! Canonical coordinate encoding for the digest-based lottery.
//!
//! Each BN254 base-field coordinate is encoded as four little-endian 64-bit
//! limbs. A G2 affine point uses `x.c0, x.c1, y.c0, y.c1`, in that order, for
//! sixteen native-field elements in total. G1 uses `x, y`, for eight elements.
//! Unlike the legacy coordinate tag,
//! this preserves every coordinate and does not reduce Fq values modulo Fr.
//! The encoding is independent of the FpChip's internal limb configuration.
//!
//! These helpers bind coordinates, not curve/subgroup membership. Assigned
//! points must come from the enclosing curve circuit's validated point cells.

use super::{
    bls_signature::{AssignedG1, AssignedG2},
    FpChip,
};
use crate::halo2_proofs::halo2curves::{
    bn256::{Fq, G1Affine, G2Affine},
    ff::PrimeField,
};
use crate::{bigint::ProperCrtUint, fields::FieldChip};
use halo2_base::{
    gates::GateInstructions,
    utils::{decompose_biguint, fe_to_biguint, BigPrimeField},
    AssignedValue, Context,
};

pub const COORDINATE_LIMBS: usize = 4;
pub const ENCODING_LIMB_BITS: usize = 64;
pub const G2_ENCODING_LEN: usize = 4 * COORDINATE_LIMBS;
pub const G1_ENCODING_LEN: usize = 2 * COORDINATE_LIMBS;

/// Encodes the canonical integer representative of one Fq coordinate.
pub fn native_coordinate_encoding<F: BigPrimeField>(coordinate: &Fq) -> [F; COORDINATE_LIMBS] {
    assert!(F::CAPACITY >= ENCODING_LIMB_BITS as u32);
    decompose_biguint(&fe_to_biguint(coordinate), COORDINATE_LIMBS, ENCODING_LIMB_BITS)
        .try_into()
        .unwrap()
}

/// Encodes already constrained CRT limbs, first requiring their integer to be
/// canonical in Fq. All output limbs remain linked to the original cells.
pub fn assigned_coordinate_encoding<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F>,
    coordinate: &ProperCrtUint<F>,
) -> [AssignedValue<F>; COORDINATE_LIMBS] {
    assert!(F::CAPACITY >= ENCODING_LIMB_BITS as u32);
    assert_eq!(coordinate.limbs().len(), fp_chip.num_limbs, "coordinate limb configuration");
    assert!(fp_chip.limb_bits * fp_chip.num_limbs >= Fq::NUM_BITS as usize);
    fp_chip.enforce_less_than_p(ctx, coordinate.clone());
    let gate = fp_chip.gate();
    let mut bits = coordinate
        .limbs()
        .iter()
        .flat_map(|&limb| gate.num_to_bits(ctx, limb, fp_chip.limb_bits))
        .collect::<Vec<_>>();
    let encoded_bits = COORDINATE_LIMBS * ENCODING_LIMB_BITS;
    // Configuration changes must neither truncate a high limb nor alter the
    // fixed-width transcript. Fq canonicality already implies these are zero.
    for bit in bits.iter().skip(encoded_bits) {
        gate.assert_is_const(ctx, bit, &F::ZERO);
    }
    bits.truncate(encoded_bits);
    if bits.len() < encoded_bits {
        let zero = ctx.load_constant(F::ZERO);
        bits.resize(encoded_bits, zero);
    }
    std::array::from_fn(|i| {
        gate.bits_to_num(ctx, &bits[i * ENCODING_LIMB_BITS..(i + 1) * ENCODING_LIMB_BITS])
    })
}

/// Canonical full public-key encoding, suitable for a registry leaf transcript.
pub fn native_g1_encoding<F: BigPrimeField>(point: &G1Affine) -> [F; G1_ENCODING_LEN] {
    let limbs = [&point.x, &point.y].map(native_coordinate_encoding::<F>);
    std::array::from_fn(|i| limbs[i / COORDINATE_LIMBS][i % COORDINATE_LIMBS])
}

/// Binds all eight registry-key limbs to the supplied assigned G1 coordinates.
/// Curve membership must be checked by the caller loading the point.
pub fn assigned_g1_encoding<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F>,
    point: &AssignedG1<F>,
) -> [AssignedValue<F>; G1_ENCODING_LEN] {
    let limbs = [&point.x, &point.y].map(|value| assigned_coordinate_encoding(ctx, fp_chip, value));
    std::array::from_fn(|i| limbs[i / COORDINATE_LIMBS][i % COORDINATE_LIMBS])
}

pub fn native_g2_encoding<F: BigPrimeField>(point: &G2Affine) -> [F; G2_ENCODING_LEN] {
    let coordinates = [&point.x.c0, &point.x.c1, &point.y.c0, &point.y.c1];
    let limbs = coordinates.map(native_coordinate_encoding::<F>);
    std::array::from_fn(|i| limbs[i / COORDINATE_LIMBS][i % COORDINATE_LIMBS])
}

pub fn assigned_g2_encoding<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F>,
    point: &AssignedG2<F>,
) -> [AssignedValue<F>; G2_ENCODING_LEN] {
    assert_eq!(point.x.0.len(), 2, "G2 x must have two Fq coordinates");
    assert_eq!(point.y.0.len(), 2, "G2 y must have two Fq coordinates");
    let coordinates = [&point.x[0], &point.x[1], &point.y[0], &point.y[1]];
    let limbs = coordinates.map(|value| assigned_coordinate_encoding(ctx, fp_chip, value));
    std::array::from_fn(|i| limbs[i / COORDINATE_LIMBS][i % COORDINATE_LIMBS])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint::ProperUint, bn254::pairing::PairingChip};
    use halo2_base::{
        gates::RangeInstructions,
        halo2_proofs::halo2curves::{bn256::Fr, ff::Field},
        utils::{biguint_to_fe, modulus, testing::base_test},
    };

    #[test]
    fn alignment_regression_coordinate_encoding_canonical_boundaries_and_configurations() {
        let r = modulus::<Fr>();
        let q = modulus::<Fq>();
        let values = [0u64.into(), &r - 1u64, r.clone(), &r + 1u64, &q - 1u64];
        assert_ne!(
            native_coordinate_encoding::<Fr>(&Fq::ONE),
            native_coordinate_encoding::<Fr>(&biguint_to_fe::<Fq>(&(&r + 1u64))),
            "Fq coordinates which alias after reduction modulo Fr must stay distinct"
        );
        for (limb_bits, num_limbs) in [(90, 3), (64, 4)] {
            base_test().k(12).lookup_bits(8).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, limb_bits, num_limbs);
                for value in &values {
                    let coordinate = biguint_to_fe::<Fq>(value);
                    let assigned = fp.load_private(ctx, coordinate);
                    let encoding = assigned_coordinate_encoding(ctx, &fp, &assigned);
                    for (limb, expected) in
                        encoding.iter().zip(native_coordinate_encoding::<Fr>(&coordinate))
                    {
                        range.gate().assert_is_const(ctx, limb, &expected);
                    }
                }
            });
        }
    }

    #[test]
    fn alignment_regression_coordinate_encoding_rejects_noncanonical_fq() {
        let q = modulus::<Fq>();
        for value in [q.clone(), &q + 1u64] {
            base_test().k(11).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                let limbs = ctx.assign_witnesses(decompose_biguint::<Fr>(&value, 3, 90));
                for &limb in &limbs {
                    range.range_check(ctx, limb, 90);
                }
                let coordinate = ProperUint(limbs).into_crt(
                    ctx,
                    range.gate(),
                    value.clone(),
                    &fp.limb_bases,
                    90,
                );
                assigned_coordinate_encoding(ctx, &fp, &coordinate);
            });
        }
    }

    #[test]
    fn alignment_regression_g2_encoding_includes_sign_and_binds_each_coordinate() {
        let point = G2Affine::generator();
        assert_ne!(native_g2_encoding::<Fr>(&point), native_g2_encoding::<Fr>(&-point));
        // Mutating one output limb of each coordinate must violate its link to
        // the assigned point even without an equality to a known encoding.
        for coordinate_index in 0..4 {
            base_test().k(12).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                let pairing = PairingChip::new(&fp);
                let assigned = pairing.load_private_g2(ctx, point);
                let encoding = assigned_g2_encoding(ctx, &fp, &assigned);
                let output = encoding[coordinate_index * COORDINATE_LIMBS];
                output.debug_prank(ctx, *output.value() + Fr::ONE);
            });
        }
    }

    #[test]
    fn certificate_regression_g1_encoding_preserves_sign_and_fr_aliases() {
        let point = G1Affine::generator();
        assert_ne!(native_g1_encoding::<Fr>(&point), native_g1_encoding::<Fr>(&-point));
        // The encoding helper also distinguishes canonical coordinate integers
        // which collide under the old reduction to Fr. This artificial point
        // tests serialization only, not the separate curve-membership check.
        let mut alias = point;
        alias.x = biguint_to_fe::<Fq>(&(&modulus::<Fr>() + 1u64));
        assert_eq!(point.x, Fq::ONE);
        assert_ne!(native_g1_encoding::<Fr>(&point), native_g1_encoding::<Fr>(&alias));
        base_test().k(12).lookup_bits(8).run(|ctx, range| {
            let fp = FpChip::<Fr>::new(range, 90, 3);
            let pairing = PairingChip::new(&fp);
            for point in [point, -point] {
                let assigned = pairing.load_private_g1(ctx, point);
                let encoding = assigned_g1_encoding(ctx, &fp, &assigned);
                for (limb, expected) in encoding.iter().zip(native_g1_encoding::<Fr>(&point)) {
                    range.gate().assert_is_const(ctx, limb, &expected);
                }
            }
        });
    }

    #[test]
    fn certificate_regression_g1_encoding_binds_both_coordinates() {
        for coordinate_index in 0..2 {
            base_test().k(11).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                let pairing = PairingChip::new(&fp);
                let assigned = pairing.load_private_g1(ctx, G1Affine::generator());
                let encoding = assigned_g1_encoding(ctx, &fp, &assigned);
                let output = encoding[coordinate_index * COORDINATE_LIMBS];
                output.debug_prank(ctx, *output.value() + Fr::ONE);
            });
        }
    }
}
