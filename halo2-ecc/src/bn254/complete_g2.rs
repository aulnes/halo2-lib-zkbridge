//! Complete group operations used before a BN254 G2 point is in the prime-order subgroup.
//!
//! Coordinates are Jacobian: `(X, Y, Z)` represents `(X/Z², Y/Z³)` when `Z != 0`.
//! Every `Z = 0` represents infinity. Inputs must already be constrained to be on
//! the curve (or be infinity); these operations do not establish that precondition.
//! Unlike the existing incomplete affine arithmetic, exceptional cases are
//! selected using constrained field equality tests and no division is performed
//! until a caller explicitly requests a nonidentity affine result.

use super::{bls_signature::AssignedG2, Fp2Chip, FpChip, FqPoint};
use crate::{
    ecc::EcPoint,
    fields::{FieldChip, Selectable},
    halo2_proofs::halo2curves::bn256::{Fq2, Fr},
};
use halo2_base::{gates::GateInstructions, utils::modulus, AssignedValue, Context};
use num_bigint::BigUint;

/// Full integer G2 cofactor. It is larger than the scalar-field modulus and
/// therefore must never be converted to an `Fr` scalar before multiplication.
pub fn g2_cofactor() -> BigUint {
    BigUint::parse_bytes(b"30644e72e131a029b85045b68181585e06ceecda572a2489345f2299c0f9fa8d", 16)
        .unwrap()
}

#[derive(Clone, Debug)]
pub struct AssignedProjectiveG2 {
    pub x: FqPoint<Fr>,
    pub y: FqPoint<Fr>,
    pub z: FqPoint<Fr>,
}

pub struct CompleteG2Chip<'a> {
    fp_chip: &'a FpChip<'a, Fr>,
}

impl<'a> CompleteG2Chip<'a> {
    pub fn new(fp_chip: &'a FpChip<'a, Fr>) -> Self {
        Self { fp_chip }
    }

    fn add_field(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>, b: &FqPoint<Fr>) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let sum = fp2.add_no_carry(ctx, a, b);
        fp2.carry_mod(ctx, sum)
    }

    fn sub_field(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>, b: &FqPoint<Fr>) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let difference = fp2.sub_no_carry(ctx, a, b);
        fp2.carry_mod(ctx, difference)
    }

    fn scale(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>, scalar: i64) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let scaled = fp2.scalar_mul_no_carry(ctx, a, scalar);
        fp2.carry_mod(ctx, scaled)
    }

    fn select(
        &self,
        ctx: &mut Context<Fr>,
        a: &AssignedProjectiveG2,
        b: &AssignedProjectiveG2,
        choose_a: AssignedValue<Fr>,
    ) -> AssignedProjectiveG2 {
        let fp2 = Fp2Chip::new(self.fp_chip);
        AssignedProjectiveG2 {
            x: fp2.select(ctx, a.x.clone(), b.x.clone(), choose_a),
            y: fp2.select(ctx, a.y.clone(), b.y.clone(), choose_a),
            z: fp2.select(ctx, a.z.clone(), b.z.clone(), choose_a),
        }
    }

    /// The fixed Jacobian representation `(1, 1, 0)` of infinity.
    pub fn identity(&self, ctx: &mut Context<Fr>) -> AssignedProjectiveG2 {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let one = fp2.load_constant(ctx, Fq2::one());
        let zero = fp2.load_constant(ctx, Fq2::zero());
        AssignedProjectiveG2 { x: one.clone(), y: one, z: zero }
    }

    /// Lift an already-constrained, nonidentity affine point to Jacobian form.
    pub fn from_affine(
        &self,
        ctx: &mut Context<Fr>,
        point: &AssignedG2<Fr>,
    ) -> AssignedProjectiveG2 {
        let fp2 = Fp2Chip::new(self.fp_chip);
        AssignedProjectiveG2 {
            x: point.x.clone(),
            y: point.y.clone(),
            z: fp2.load_constant(ctx, Fq2::one()),
        }
    }

    pub fn is_identity(
        &self,
        ctx: &mut Context<Fr>,
        point: &AssignedProjectiveG2,
    ) -> AssignedValue<Fr> {
        Fp2Chip::new(self.fp_chip).is_zero(ctx, point.z.clone())
    }

    /// Doubling on a short Weierstrass curve with `a = 0` (Jacobian dbl-2009-l).
    /// The polynomial formula also returns infinity when `Y = 0` or `Z = 0`.
    pub fn double(
        &self,
        ctx: &mut Context<Fr>,
        point: &AssignedProjectiveG2,
    ) -> AssignedProjectiveG2 {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let a = fp2.mul(ctx, &point.x, &point.x);
        let b = fp2.mul(ctx, &point.y, &point.y);
        let c = fp2.mul(ctx, &b, &b);
        let x_plus_b = self.add_field(ctx, &point.x, &b);
        let d = fp2.mul(ctx, &x_plus_b, &x_plus_b);
        let d = self.sub_field(ctx, &d, &a);
        let d = self.sub_field(ctx, &d, &c);
        let d = self.scale(ctx, &d, 2);
        let e = self.scale(ctx, &a, 3);
        let f = fp2.mul(ctx, &e, &e);
        let two_d = self.scale(ctx, &d, 2);
        let x = self.sub_field(ctx, &f, &two_d);
        let d_minus_x = self.sub_field(ctx, &d, &x);
        let y = fp2.mul(ctx, &e, &d_minus_x);
        let eight_c = self.scale(ctx, &c, 8);
        let y = self.sub_field(ctx, &y, &eight_c);
        let yz = fp2.mul(ctx, &point.y, &point.z);
        let z = self.scale(ctx, &yz, 2);
        AssignedProjectiveG2 { x, y, z }
    }

    /// Complete addition: generic Jacobian add-2007-bl plus constrained
    /// selections for equal points, inverse points and either infinity input.
    pub fn add(
        &self,
        ctx: &mut Context<Fr>,
        p: &AssignedProjectiveG2,
        q: &AssignedProjectiveG2,
    ) -> AssignedProjectiveG2 {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let z1z1 = fp2.mul(ctx, &p.z, &p.z);
        let z2z2 = fp2.mul(ctx, &q.z, &q.z);
        let u1 = fp2.mul(ctx, &p.x, &z2z2);
        let u2 = fp2.mul(ctx, &q.x, &z1z1);
        let z2_cubed = fp2.mul(ctx, &q.z, &z2z2);
        let z1_cubed = fp2.mul(ctx, &p.z, &z1z1);
        let s1 = fp2.mul(ctx, &p.y, &z2_cubed);
        let s2 = fp2.mul(ctx, &q.y, &z1_cubed);
        let h = self.sub_field(ctx, &u2, &u1);
        let s_diff = self.sub_field(ctx, &s2, &s1);
        let r = self.scale(ctx, &s_diff, 2);
        let two_h = self.scale(ctx, &h, 2);
        let i = fp2.mul(ctx, &two_h, &two_h);
        let j = fp2.mul(ctx, &h, &i);
        let v = fp2.mul(ctx, &u1, &i);
        let r_squared = fp2.mul(ctx, &r, &r);
        let x = self.sub_field(ctx, &r_squared, &j);
        let two_v = self.scale(ctx, &v, 2);
        let x = self.sub_field(ctx, &x, &two_v);
        let v_minus_x = self.sub_field(ctx, &v, &x);
        let y = fp2.mul(ctx, &r, &v_minus_x);
        let s1j = fp2.mul(ctx, &s1, &j);
        let two_s1j = self.scale(ctx, &s1j, 2);
        let y = self.sub_field(ctx, &y, &two_s1j);
        let z_sum = self.add_field(ctx, &p.z, &q.z);
        let z = fp2.mul(ctx, &z_sum, &z_sum);
        let z = self.sub_field(ctx, &z, &z1z1);
        let z = self.sub_field(ctx, &z, &z2z2);
        let z = fp2.mul(ctx, &z, &h);
        let generic = AssignedProjectiveG2 { x, y, z };

        let same_x = fp2.is_zero(ctx, h);
        let same_y = fp2.is_zero(ctx, s_diff);
        let doubled = self.double(ctx, p);
        let infinity = self.identity(ctx);
        let exceptional = self.select(ctx, &doubled, &infinity, same_y);
        let result = self.select(ctx, &exceptional, &generic, same_x);
        let p_is_identity = self.is_identity(ctx, p);
        let q_is_identity = self.is_identity(ctx, q);
        let result = self.select(ctx, q, &result, p_is_identity);
        self.select(ctx, p, &result, q_is_identity)
    }

    /// Multiply by a public, arbitrary-length integer. The loop shape depends
    /// only on this constant; no assumption about the input point's order is used.
    pub fn mul_const(
        &self,
        ctx: &mut Context<Fr>,
        point: &AssignedProjectiveG2,
        scalar: &BigUint,
    ) -> AssignedProjectiveG2 {
        if scalar.bits() == 0 {
            return self.identity(ctx);
        }
        // The most significant bit is one, so initialize with P rather than
        // doing a redundant complete addition to infinity.
        let mut acc = point.clone();
        for bit in (0..scalar.bits() - 1).rev() {
            acc = self.double(ctx, &acc);
            if scalar.bit(bit) {
                acc = self.add(ctx, &acc, point);
            }
        }
        acc
    }

    /// Require an already curve-checked, nonidentity affine point to lie in G2.
    ///
    /// Multiplication uses the complete formulas because subgroup membership
    /// is what this method establishes. The scalar is the full integer order
    /// `r`, never its representation in `Fr` (which would be zero).
    /// This method does not replace the caller's curve/nonidentity checks.
    pub fn assert_prime_subgroup(&self, ctx: &mut Context<Fr>, point: &AssignedG2<Fr>) {
        let projective = self.from_affine(ctx, point);
        let product = self.mul_const(ctx, &projective, &modulus::<Fr>());
        let is_identity = self.is_identity(ctx, &product);
        self.fp_chip.gate().assert_is_const(ctx, &is_identity, &Fr::one());
    }

    /// Convert to affine and constrain that the result is nonidentity.
    pub fn to_affine(&self, ctx: &mut Context<Fr>, point: &AssignedProjectiveG2) -> AssignedG2<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let one = fp2.load_constant(ctx, Fq2::one());
        let inverse_z = fp2.divide(ctx, one, point.z.clone());
        let inverse_z2 = fp2.mul(ctx, &inverse_z, &inverse_z);
        let inverse_z3 = fp2.mul(ctx, &inverse_z2, &inverse_z);
        let x = fp2.mul(ctx, &point.x, &inverse_z2);
        let y = fp2.mul(ctx, &point.y, &inverse_z3);
        EcPoint::new(x, y)
    }

    /// Add two mapped affine points and clear the full G2 cofactor. The output
    /// is constrained nonidentity, as required by the BLS verification wrapper.
    pub fn combine_and_clear(
        &self,
        ctx: &mut Context<Fr>,
        p: &AssignedG2<Fr>,
        q: &AssignedG2<Fr>,
    ) -> AssignedG2<Fr> {
        let p = self.from_affine(ctx, p);
        let q = self.from_affine(ctx, q);
        let sum = self.add(ctx, &p, &q);
        let cleared = self.mul_const(ctx, &sum, &g2_cofactor());
        self.to_affine(ctx, &cleared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ff::Field;
    use crate::halo2_proofs::halo2curves::{
        bn256::{Fq, G2Affine, G2},
        group::{cofactor::CofactorGroup, prime::PrimeCurveAffine, Curve},
        CurveAffine,
    };
    use halo2_base::utils::testing::base_test;

    fn load(fp2: &Fp2Chip<Fr>, ctx: &mut Context<Fr>, point: G2Affine) -> AssignedG2<Fr> {
        EcPoint::new(fp2.load_private(ctx, point.x), fp2.load_private(ctx, point.y))
    }

    fn assert_affine(
        fp2: &Fp2Chip<Fr>,
        ctx: &mut Context<Fr>,
        actual: &AssignedG2<Fr>,
        expected: G2Affine,
    ) {
        let x = fp2.load_constant(ctx, expected.x);
        let y = fp2.load_constant(ctx, expected.y);
        fp2.assert_equal(ctx, actual.x.clone(), x);
        fp2.assert_equal(ctx, actual.y.clone(), y);
    }

    #[test]
    fn alignment_regression_complete_addition_handles_exceptional_cases() {
        base_test().k(14).lookup_bits(13).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let fp2 = Fp2Chip::new(&fp);
            let chip = CompleteG2Chip::new(&fp);
            let p_native = G2Affine::generator();
            let q_native = (p_native * Fr::from(7)).to_affine();
            let p_affine = load(&fp2, ctx, p_native);
            let q_affine = load(&fp2, ctx, q_native);
            let minus_p_affine = load(&fp2, ctx, -p_native);
            let p = chip.from_affine(ctx, &p_affine);
            let q = chip.from_affine(ctx, &q_affine);
            let minus_p = chip.from_affine(ctx, &minus_p_affine);
            let identity = chip.identity(ctx);

            let sum = chip.add(ctx, &p, &q);
            let affine = chip.to_affine(ctx, &sum);
            assert_affine(&fp2, ctx, &affine, (p_native + q_native).to_affine());
            let sum = chip.add(ctx, &p, &p);
            let affine = chip.to_affine(ctx, &sum);
            assert_affine(&fp2, ctx, &affine, (p_native * Fr::from(2)).to_affine());
            // Equality is projective equality, not equality of stored limbs.
            let lambda = fp2.load_constant(ctx, Fq2 { c0: Fq::from(5), c1: Fq::one() });
            let lambda2 = fp2.mul(ctx, &lambda, &lambda);
            let lambda3 = fp2.mul(ctx, &lambda2, &lambda);
            let rescaled_p = AssignedProjectiveG2 {
                x: fp2.mul(ctx, &p.x, &lambda2),
                y: fp2.mul(ctx, &p.y, &lambda3),
                z: lambda,
            };
            let sum = chip.add(ctx, &p, &rescaled_p);
            let affine = chip.to_affine(ctx, &sum);
            assert_affine(&fp2, ctx, &affine, (p_native * Fr::from(2)).to_affine());
            let sum = chip.add(ctx, &p, &minus_p);
            let is_identity = chip.is_identity(ctx, &sum);
            fp2.gate().assert_is_const(ctx, &is_identity, &Fr::one());
            for (left, right) in [(&p, &identity), (&identity, &p)] {
                let sum = chip.add(ctx, left, right);
                let affine = chip.to_affine(ctx, &sum);
                assert_affine(&fp2, ctx, &affine, p_native);
            }
            let double_identity = chip.double(ctx, &identity);
            let is_identity = chip.is_identity(ctx, &double_identity);
            fp2.gate().assert_is_const(ctx, &is_identity, &Fr::one());
            let zero_product = chip.mul_const(ctx, &p, &BigUint::from(0u64));
            let is_identity = chip.is_identity(ctx, &zero_product);
            fp2.gate().assert_is_const(ctx, &is_identity, &Fr::one());
        });
    }

    #[test]
    fn alignment_regression_affine_conversion_rejects_identity() {
        base_test().k(12).lookup_bits(11).expect_satisfied(false).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let chip = CompleteG2Chip::new(&fp);
            let identity = chip.identity(ctx);
            chip.to_affine(ctx, &identity);
        });
    }

    #[test]
    fn alignment_regression_complete_addition_rejects_wrong_result() {
        base_test().k(13).lookup_bits(12).expect_satisfied(false).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let fp2 = Fp2Chip::new(&fp);
            let chip = CompleteG2Chip::new(&fp);
            let native = G2Affine::generator();
            let affine = load(&fp2, ctx, native);
            let p = chip.from_affine(ctx, &affine);
            let doubled = chip.double(ctx, &p);
            let actual = chip.to_affine(ctx, &doubled);
            assert_affine(&fp2, ctx, &actual, (native * Fr::from(3)).to_affine());
        });
    }

    #[test]
    fn alignment_regression_full_integer_cofactor_matches_native_on_non_subgroup_point() {
        // Deliberately start on the full curve, not with a generator multiple:
        // reducing h into Fr would be wrong for this input.
        let native = (0u64..)
            .find_map(|i| {
                let x = Fq2 { c0: Fq::from(i), c1: Fq::one() };
                let rhs = x * x * x + G2Affine::b();
                let y = Option::<Fq2>::from(rhs.sqrt())?;
                let point = Option::<G2Affine>::from(G2Affine::from_xy(x, y))?;
                (!bool::from(G2::from(point).is_torsion_free())).then_some(point)
            })
            .unwrap();
        let expected = G2::from(native).clear_cofactor().to_affine();
        assert!(!bool::from(expected.is_identity()));
        base_test().k(18).lookup_bits(15).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let fp2 = Fp2Chip::new(&fp);
            let chip = CompleteG2Chip::new(&fp);
            let affine = load(&fp2, ctx, native);
            let p = chip.from_affine(ctx, &affine);
            let cleared = chip.mul_const(ctx, &p, &g2_cofactor());
            let actual = chip.to_affine(ctx, &cleared);
            assert_affine(&fp2, ctx, &actual, expected);
        });
    }

    #[test]
    fn certificate_regression_subgroup_accepts_generator_multiple() {
        let native = (G2Affine::generator() * Fr::from(17)).to_affine();
        assert!(bool::from(G2::from(native).is_torsion_free()));
        base_test().k(18).lookup_bits(15).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let pairing = crate::bn254::pairing::PairingChip::new(&fp);
            let assigned = pairing.load_private_g2(ctx, native);
            CompleteG2Chip::new(&fp).assert_prime_subgroup(ctx, &assigned);
        });
    }

    #[test]
    fn certificate_regression_subgroup_rejects_nonzero_torsion_component() {
        // Curve membership alone accepts this nonidentity point. Its nonzero
        // torsion component must be rejected by the full [r]P = infinity test.
        let native = (0u64..)
            .find_map(|i| {
                let x = Fq2 { c0: Fq::from(i), c1: Fq::one() };
                let y = Option::<Fq2>::from((x * x * x + G2Affine::b()).sqrt())?;
                let point = Option::<G2Affine>::from(G2Affine::from_xy(x, y))?;
                (!bool::from(G2::from(point).is_torsion_free())).then_some(point)
            })
            .unwrap();
        assert!(!bool::from(native.is_identity()));
        base_test().k(18).lookup_bits(15).expect_satisfied(false).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let pairing = crate::bn254::pairing::PairingChip::new(&fp);
            let assigned = pairing.load_private_g2(ctx, native);
            CompleteG2Chip::new(&fp).assert_prime_subgroup(ctx, &assigned);
        });
    }
}
