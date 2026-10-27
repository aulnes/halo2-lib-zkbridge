//! Experimental `H2C-BN254-v1` message-digest-to-G2 suite.
//!
//! The input is `(registry_root, message_digest)`, two BN254 scalar-field
//! elements. This matches the *boundary* of Mithril's inner certificate; it
//! neither hashes raw message bytes nor implements Mithril's Jubjub suite.
//! The complete mapping is constrained here, rather than accepting a point
//! computed outside the circuit.
//!
//! For each of four Fq coefficients, two domain-separated Poseidon(3,2,8,57)
//! outputs `a,b` are lifted as canonical integers and reduced as `(a+r*b) mod q`.
//! The resulting two Fq2 elements are mapped by RFC 9380 Appendix F.1 SVDW
//! (A=0, Z=1), added, and multiplied by the full G2 cofactor. This is a custom
//! Poseidon suite, **not** an RFC-named XMD suite or byte-compatible with gnark.
//! Its hash-to-field distribution argument assumes independent uniform Fr
//! outputs; the residue bias is bounded by q/r^2. It has not been audited.
//! The astronomically rare identity output is outside this BLS-facing API's
//! domain: native code rejects it and the circuit constrains it away.

use super::{bls_signature::AssignedG2, complete_g2::CompleteG2Chip, Fp2Chip, FpChip, FqPoint};
use crate::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::{fp, FieldChip, Selectable},
    halo2_proofs::halo2curves::{
        bn256::{Fq, Fq2, Fr, G2Affine, G2},
        ff::{Field, PrimeField},
        group::{cofactor::CofactorGroup, Curve, Group},
        CurveAffine,
    },
};
use halo2_base::{
    gates::GateInstructions,
    poseidon::hasher::PoseidonHasher,
    utils::{biguint_to_fe, fe_to_biguint, modulus},
    AssignedValue, Context,
};
use num_bigint::BigUint;
use poseidon::Poseidon;

/// The suite tag is the little-endian integer encoding of these ASCII bytes.
pub const SUITE_ID: &[u8] = b"H2C-BN254-v1";

fn suite_tag() -> Fr {
    biguint_to_fe(&BigUint::from_bytes_le(SUITE_ID))
}

fn native_poseidon(values: &[Fr]) -> Fr {
    let mut hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
    hasher.update(values);
    hasher.squeeze()
}

/// Canonical RFC 9380 sgn0 for Fq2 in coefficient order (c0, c1).
fn sgn0(value: Fq2) -> bool {
    bool::from(value.c0.is_odd())
        || (bool::from(value.c0.is_zero()) && bool::from(value.c1.is_odd()))
}

/// Constants derived from Z=1 and the BN254 twist equation, rather than
/// unchecked decimal constants. The root c3 is fixed by sgn0(c3)=0.
fn svdw_constants() -> [Fq2; 4] {
    let three = Fq2::from(3);
    let c1 = Fq2::ONE + G2Affine::b();
    let c2 = -Fq2::from(2).invert().unwrap();
    let mut c3 = (-c1 * three).sqrt().unwrap();
    if sgn0(c3) {
        c3 = -c3;
    }
    let c4 = -Fq2::from(4) * c1 * three.invert().unwrap();
    [c1, c2, c3, c4]
}

/// SVDW before cofactor clearing; the result is on the full twist curve.
/// This follows RFC 9380 Appendix F.1, with A=0, Z=1.
pub(crate) fn map_to_curve(u: Fq2) -> G2Affine {
    let [c1, c2, c3, c4] = svdw_constants();
    let t = u.square() * c1;
    let plus = Fq2::ONE + t;
    let minus = Fq2::ONE - t;
    let inverse = (plus * minus).invert().unwrap_or(Fq2::ZERO);
    let offset = u * minus * inverse * c3;
    let x1 = c2 - offset;
    let x2 = c2 + offset;
    let x3 = (plus.square() * inverse).square() * c4 + Fq2::ONE;
    let rhs = |x: Fq2| x.square() * x + G2Affine::b();
    let x = if bool::from(rhs(x1).sqrt().is_some()) {
        x1
    } else if bool::from(rhs(x2).sqrt().is_some()) {
        x2
    } else {
        x3
    };
    let mut y = rhs(x).sqrt().unwrap();
    if sgn0(y) != sgn0(u) {
        y = -y;
    }
    G2Affine::from_xy(x, y).unwrap()
}

fn hash_to_field(root: Fr, message_digest: Fr) -> [Fq2; 2] {
    let q = modulus::<Fq>();
    let r = modulus::<Fr>();
    let coefficients: [Fq; 4] = std::array::from_fn(|i| {
        let output = |part| {
            fe_to_biguint(&native_poseidon(&[
                suite_tag(),
                root,
                message_digest,
                Fr::from(i as u64),
                Fr::from(part),
            ]))
        };
        biguint_to_fe(&((output(0) + &r * output(1)) % &q))
    });
    [
        Fq2 { c0: coefficients[0], c1: coefficients[1] },
        Fq2 { c0: coefficients[2], c1: coefficients[3] },
    ]
}

/// Compute the same experimental digest-to-G2 mapping as [`MessageHashChip`].
/// This helper is for native signing/fixtures; it is not constant-time.
pub fn hash_message(root: Fr, message_digest: Fr) -> G2Affine {
    let [u0, u1] = hash_to_field(root, message_digest);
    let point = (G2::from(map_to_curve(u0)) + G2::from(map_to_curve(u1))).clear_cofactor();
    assert!(!bool::from(point.is_identity()), "identity is outside the BLS message domain");
    point.to_affine()
}

/// Requires an initialized Poseidon hasher with the suite's 8/57 round spec.
pub struct MessageHashChip<'a> {
    fp_chip: &'a FpChip<'a, Fr>,
    poseidon: &'a PoseidonHasher<Fr, 3, 2>,
}

impl<'a> MessageHashChip<'a> {
    pub fn new(fp_chip: &'a FpChip<'a, Fr>, poseidon: &'a PoseidonHasher<Fr, 3, 2>) -> Self {
        Self { fp_chip, poseidon }
    }

    /// Bind a canonical Fr integer representation to the original native cell.
    /// An Fq-only bound would allow x+r to alias x for small x, since q>r.
    fn lift_scalar(&self, ctx: &mut Context<Fr>, value: AssignedValue<Fr>) -> ProperCrtUint<Fr> {
        let scalar_chip = fp::FpChip::<Fr, Fr>::new(
            self.fp_chip.range,
            self.fp_chip.limb_bits,
            self.fp_chip.num_limbs,
        );
        let lifted = scalar_chip.load_private(ctx, *value.value());
        self.bind_canonical_lift(ctx, value, &lifted);
        // The identical limb/native representation is now a valid Fq integer:
        // its value is less than r, and r < q.
        lifted
    }

    fn bind_canonical_lift(
        &self,
        ctx: &mut Context<Fr>,
        value: AssignedValue<Fr>,
        lifted: &ProperCrtUint<Fr>,
    ) {
        let scalar_chip = fp::FpChip::<Fr, Fr>::new(
            self.fp_chip.range,
            self.fp_chip.limb_bits,
            self.fp_chip.num_limbs,
        );
        scalar_chip.enforce_less_than_p(ctx, lifted.clone());
        ctx.constrain_equal(lifted.native(), &value);
    }

    fn hash_to_field(
        &self,
        ctx: &mut Context<Fr>,
        root: AssignedValue<Fr>,
        message: AssignedValue<Fr>,
    ) -> [FqPoint<Fr>; 2] {
        let gate = self.fp_chip.gate();
        let tag = ctx.load_constant(suite_tag());
        let r = self.fp_chip.load_constant(ctx, biguint_to_fe(&modulus::<Fr>()));
        let coefficients: Vec<_> = (0..4)
            .map(|i| {
                let component = ctx.load_constant(Fr::from(i));
                let mut outputs = Vec::with_capacity(2);
                for part in 0..2 {
                    let part = ctx.load_constant(Fr::from(part));
                    let output = self.poseidon.hash_fix_len_array(
                        ctx,
                        gate,
                        &[tag, root, message, component, part],
                    );
                    outputs.push(self.lift_scalar(ctx, output));
                }
                let rb = self.fp_chip.mul(ctx, &r, &outputs[1]);
                let sum = self.fp_chip.add_no_carry(ctx, &outputs[0], &rb);
                self.fp_chip.carry_mod(ctx, sum)
            })
            .collect();
        [
            crate::fields::vector::FieldVector(coefficients[0..2].to_vec()),
            crate::fields::vector::FieldVector(coefficients[2..4].to_vec()),
        ]
    }

    fn add(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>, b: &FqPoint<Fr>) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let sum = fp2.add_no_carry(ctx, a, b);
        fp2.carry_mod(ctx, sum)
    }

    fn sub(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>, b: &FqPoint<Fr>) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let diff = fp2.sub_no_carry(ctx, a, b);
        fp2.carry_mod(ctx, diff)
    }

    /// Total inverse with a uniquely constrained zero output at zero input.
    fn inv0(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let a_value = fp2.get_assigned_value(&a.into());
        let inverse = fp2.load_private(ctx, a_value.invert().unwrap_or(Fq2::ZERO));
        self.constrain_inverse(ctx, a, &inverse);
        inverse
    }

    fn constrain_inverse(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>, inverse: &FqPoint<Fr>) {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let zero = fp2.is_zero(ctx, a.clone());
        let one_fp2 = fp2.load_constant(ctx, Fq2::ONE);
        let zero_fp2 = fp2.load_constant(ctx, Fq2::ZERO);
        let expected = fp2.select(ctx, zero_fp2.clone(), one_fp2, zero);
        let product = fp2.mul(ctx, a, inverse);
        fp2.assert_equal(ctx, product, expected);
        let inverse_at_zero = fp2.select(ctx, inverse.clone(), zero_fp2.clone(), zero);
        fp2.assert_equal(ctx, inverse_at_zero, zero_fp2);
    }

    /// Prove quadratic character without exponentiation. The fixed eta=9+i
    /// is a nonsquare in Fq2, since its norm 82 is a nonsquare in Fq.
    /// For nonzero a, exactly one of a and eta*a has a square root.
    fn is_square(
        &self,
        ctx: &mut Context<Fr>,
        a: &FqPoint<Fr>,
    ) -> (AssignedValue<Fr>, FqPoint<Fr>) {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let value = fp2.get_assigned_value(&a.into());
        let eta_value = Fq2 { c0: Fq::from(9), c1: Fq::ONE };
        let square = bool::from(value.sqrt().is_some());
        let bit = ctx.load_witness(Fr::from(square as u64));
        let root_value = if square { value } else { value * eta_value }.sqrt().unwrap();
        let root = fp2.load_private(ctx, root_value);
        self.constrain_square_character(ctx, a, bit, &root);
        (bit, root)
    }

    fn constrain_square_character(
        &self,
        ctx: &mut Context<Fr>,
        a: &FqPoint<Fr>,
        bit: AssignedValue<Fr>,
        root: &FqPoint<Fr>,
    ) {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let gate = self.fp_chip.gate();
        gate.assert_bit(ctx, bit);
        let eta = fp2.load_constant(ctx, Fq2 { c0: Fq::from(9), c1: Fq::ONE });
        let eta_a = fp2.mul(ctx, &eta, a);
        let selected = fp2.select(ctx, a.clone(), eta_a, bit);
        let squared_root = fp2.mul(ctx, root, root);
        fp2.assert_equal(ctx, squared_root, selected);
        // Both alternatives vanish for zero, so explicitly choose the square
        // branch there to preserve SVDW's specified deterministic map.
        let zero = fp2.is_zero(ctx, a.clone());
        let not_square = gate.not(ctx, bit);
        let invalid_zero = gate.and(ctx, zero, not_square);
        gate.assert_is_const(ctx, &invalid_zero, &Fr::ZERO);
    }

    fn sign(&self, ctx: &mut Context<Fr>, a: &FqPoint<Fr>) -> AssignedValue<Fr> {
        let gate = self.fp_chip.gate();
        let c0_even = self.fp_chip.is_even(ctx, &a[0]);
        let c1_even = self.fp_chip.is_even(ctx, &a[1]);
        let c0_zero = self.fp_chip.is_zero(ctx, a[0].clone());
        let even = GateInstructions::select(gate, ctx, c1_even, c0_even, c0_zero);
        gate.not(ctx, even)
    }

    fn curve_rhs(&self, ctx: &mut Context<Fr>, x: &FqPoint<Fr>) -> FqPoint<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let x2 = fp2.mul(ctx, x, x);
        let x3 = fp2.mul(ctx, &x2, x);
        let b = fp2.load_constant(ctx, G2Affine::b());
        self.add(ctx, &x3, &b)
    }

    /// Constrain SVDW's inverse, quadratic-character decisions, root and sign.
    fn map_to_curve(&self, ctx: &mut Context<Fr>, u: &FqPoint<Fr>) -> AssignedG2<Fr> {
        let fp2 = Fp2Chip::new(self.fp_chip);
        let gate = self.fp_chip.gate();
        let [c1, c2, c3, c4] = svdw_constants().map(|c| fp2.load_constant(ctx, c));
        let one = fp2.load_constant(ctx, Fq2::ONE);
        let u2 = fp2.mul(ctx, u, u);
        let t = fp2.mul(ctx, &u2, &c1);
        let plus = self.add(ctx, &one, &t);
        let minus = self.sub(ctx, &one, &t);
        let denominator = fp2.mul(ctx, &plus, &minus);
        let inverse = self.inv0(ctx, &denominator);
        let offset = fp2.mul(ctx, u, &minus);
        let offset = fp2.mul(ctx, &offset, &inverse);
        let offset = fp2.mul(ctx, &offset, &c3);
        let x1 = self.sub(ctx, &c2, &offset);
        let x2 = self.add(ctx, &c2, &offset);
        let rhs1 = self.curve_rhs(ctx, &x1);
        let (first_square, _) = self.is_square(ctx, &rhs1);
        let rhs2 = self.curve_rhs(ctx, &x2);
        let (second_square, _) = self.is_square(ctx, &rhs2);
        let not_first = gate.not(ctx, first_square);
        let use_second = gate.and(ctx, second_square, not_first);
        let x3 = fp2.mul(ctx, &plus, &plus);
        let x3 = fp2.mul(ctx, &x3, &inverse);
        let x3 = fp2.mul(ctx, &x3, &x3);
        let x3 = fp2.mul(ctx, &x3, &c4);
        let x3 = self.add(ctx, &x3, &one);
        let x = fp2.select(ctx, x1, x3, first_square);
        let x = fp2.select(ctx, x2, x, use_second);
        let rhs = self.curve_rhs(ctx, &x);
        let rhs_value = fp2.get_assigned_value(&(&rhs).into());
        let y = fp2.load_private(ctx, rhs_value.sqrt().unwrap());
        let y2 = fp2.mul(ctx, &y, &y);
        fp2.assert_equal(ctx, y2, rhs);
        let u_sign = self.sign(ctx, u);
        let y_sign = self.sign(ctx, &y);
        let same_sign = gate.is_equal(ctx, u_sign, y_sign);
        let negative_y = fp2.negate(ctx, y.clone());
        let y = fp2.select(ctx, y, negative_y, same_sign);
        EcPoint::new(x, y)
    }

    /// The caller exposes or otherwise binds root/message to its statement.
    /// This method reuses those exact assigned cells throughout the mapping.
    pub fn hash_assigned(
        &self,
        ctx: &mut Context<Fr>,
        root: AssignedValue<Fr>,
        message_digest: AssignedValue<Fr>,
    ) -> AssignedG2<Fr> {
        let [u0, u1] = self.hash_to_field(ctx, root, message_digest);
        let p0 = self.map_to_curve(ctx, &u0);
        let p1 = self.map_to_curve(ctx, &u1);
        CompleteG2Chip::new(self.fp_chip).combine_and_clear(ctx, &p0, &p1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::{poseidon::hasher::spec::OptimizedPoseidonSpec, utils::testing::base_test};

    fn initialized_hasher(ctx: &mut Context<Fr>, fp: &FpChip<Fr>) -> PoseidonHasher<Fr, 3, 2> {
        let mut hasher = PoseidonHasher::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
        hasher.initialize_consts(ctx, fp.gate());
        hasher
    }

    #[test]
    fn alignment_regression_message_native_mapping_properties() {
        let eta = Fq2 { c0: Fq::from(9), c1: Fq::ONE };
        assert!(bool::from(eta.sqrt().is_none()));
        assert!(bool::from(Fq::from(82).sqrt().is_none()));
        assert!(!sgn0(svdw_constants()[2]));
        for i in 0..16 {
            let u = Fq2 { c0: Fq::from(i), c1: Fq::from(i * 7) };
            let mapped = map_to_curve(u);
            assert!(bool::from(mapped.is_on_curve()));
            assert_eq!(sgn0(mapped.y), sgn0(u));
            let hashed = hash_message(Fr::from(19), Fr::from(i));
            assert!(bool::from(G2::from(hashed).is_torsion_free()));
            assert!(!bool::from(G2::from(hashed).is_identity()));
        }
        assert_ne!(hash_message(Fr::ONE, Fr::from(2)), hash_message(Fr::from(2), Fr::ONE));
    }

    // Independent pre-cofactor map vectors from gnark-crypto, pinned at
    // b3b6f0e1e104f8d1aca41b6a68aed2bcdaa07939, hash_vectors_test.go:88.
    // https://github.com/Consensys-Incorporated/gnark-crypto/blob/b3b6f0e1e104f8d1aca41b6a68aed2bcdaa07939/ecc/bn254/hash_vectors_test.go#L88
    // These test SVDW only: our Poseidon expansion and full cofactor suite are
    // deliberately different from gnark's XMD suite and effective cofactor.
    #[test]
    fn alignment_regression_message_gnark_map_vectors() {
        let fq = |s: &str| Fq::from_str_vartime(s).unwrap();
        let vectors = [
            [
                "20137808912851667062035976856602818236747905495088974922724698435521868288711",
                "10914081414532318428788371952655185933658856500524056428677634349002436771005",
                "3219678904083239153611991099639067526519011707800859383515749198133307861797",
                "4840632783943267929460355417792673968117748748591257346027989099060040694328",
                "20094105964899993986891012649404226446948327024003820779703132455640266705583",
                "7793772943923813372180506775375566751777576354850841676616264558060697214993",
            ],
            [
                "12749938097459350112373927900718891214846269031101262698563655023620154602803",
                "15989048767193036968813394630414887900446878286238597875452219988350848861115",
                "1638946587108629780181372034098582762311394309721031341668719698485338651653",
                "12638358565844337031624411847193615438793160093107336650426793883735338280940",
                "15647472230264241572312420284434333085778908811609588640626490166644321670789",
                "2261048731520970935907951996800890376329202439460795694957245871515445864198",
            ],
        ];
        for vector in vectors {
            let [u0, u1, x0, x1, y0, y1] = vector.map(fq);
            let actual = map_to_curve(Fq2 { c0: u0, c1: u1 });
            assert_eq!(actual.x, Fq2 { c0: x0, c1: x1 });
            assert_eq!(actual.y, Fq2 { c0: y0, c1: y1 });
        }
    }

    #[test]
    fn alignment_regression_message_map_matches_native() {
        base_test().k(14).lookup_bits(13).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let hasher = initialized_hasher(ctx, &fp);
            let chip = MessageHashChip::new(&fp, &hasher);
            let fp2 = Fp2Chip::new(&fp);
            let mut cases = vec![
                Fq2::ZERO,
                Fq2::ONE,
                Fq2 { c0: Fq::ZERO, c1: Fq::from(3) },
                Fq2 { c0: Fq::from(7), c1: Fq::from(29) },
            ];
            // Exercise SVDW's exceptional denominator-zero inputs whenever
            // the corresponding field square root exists.
            let reciprocal_c1 = svdw_constants()[0].invert().unwrap();
            for square in [reciprocal_c1, -reciprocal_c1] {
                if let Some(root) = Option::<Fq2>::from(square.sqrt()) {
                    cases.extend([root, -root]);
                }
            }
            for u in cases {
                let assigned_u = fp2.load_private(ctx, u);
                let actual = chip.map_to_curve(ctx, &assigned_u);
                let expected = map_to_curve(u);
                let expected_x = fp2.load_constant(ctx, expected.x);
                let expected_y = fp2.load_constant(ctx, expected.y);
                fp2.assert_equal(ctx, actual.x, expected_x);
                fp2.assert_equal(ctx, actual.y, expected_y);
            }
        });
    }

    #[test]
    fn alignment_regression_message_hash_to_field_matches_native() {
        base_test().k(14).lookup_bits(13).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let hasher = initialized_hasher(ctx, &fp);
            let chip = MessageHashChip::new(&fp, &hasher);
            let fp2 = Fp2Chip::new(&fp);
            let root = ctx.load_witness(-Fr::ONE);
            let msg = ctx.load_witness(Fr::from(314));
            let actual = chip.hash_to_field(ctx, root, msg);
            for (actual, expected) in actual.into_iter().zip(hash_to_field(-Fr::ONE, Fr::from(314)))
            {
                let expected = fp2.load_constant(ctx, expected);
                fp2.assert_equal(ctx, actual, expected);
            }
        });
    }

    #[test]
    fn alignment_regression_message_rejects_fr_lift_alias() {
        base_test().k(11).lookup_bits(10).expect_satisfied(false).run(|ctx, range| {
            let fp = FpChip::new(range, 90, 3);
            let hasher = initialized_hasher(ctx, &fp);
            let chip = MessageHashChip::new(&fp, &hasher);
            let native = ctx.load_witness(Fr::ONE);
            // Canonical in Fq and congruent to one modulo Fr, but it must not
            // be accepted as the canonical integer lift of that Fr element.
            let alias = fp.load_private(ctx, biguint_to_fe(&(modulus::<Fr>() + 1u64)));
            chip.bind_canonical_lift(ctx, native, &alias);
        });
    }

    #[test]
    fn alignment_regression_message_rejects_square_branch_tampering() {
        for value in [Fq2::ZERO, Fq2::ONE, Fq2 { c0: Fq::from(9), c1: Fq::ONE }] {
            base_test().k(11).lookup_bits(10).expect_satisfied(false).run(|ctx, range| {
                let fp = FpChip::new(range, 90, 3);
                let hasher = initialized_hasher(ctx, &fp);
                let chip = MessageHashChip::new(&fp, &hasher);
                let fp2 = Fp2Chip::new(&fp);
                let input = fp2.load_private(ctx, value);
                let wrong_bit =
                    ctx.load_witness(Fr::from(!bool::from(value.sqrt().is_some()) as u64));
                let arbitrary_root = fp2.load_private(ctx, Fq2::ZERO);
                chip.constrain_square_character(ctx, &input, wrong_bit, &arbitrary_root);
            });
        }
    }

    #[test]
    fn alignment_regression_message_rejects_sqrt_inverse_and_sign_tampering() {
        for kind in 0..4 {
            base_test().k(11).lookup_bits(10).expect_satisfied(false).run(|ctx, range| {
                let fp = FpChip::new(range, 90, 3);
                let hasher = initialized_hasher(ctx, &fp);
                let chip = MessageHashChip::new(&fp, &hasher);
                let fp2 = Fp2Chip::new(&fp);
                let input_value = if kind == 2 { Fq2::ZERO } else { Fq2::from(4) };
                let input = fp2.load_private(ctx, input_value);
                match kind {
                    0 => {
                        let bit = ctx.load_witness(Fr::ONE);
                        let wrong_root = fp2.load_private(ctx, Fq2::from(3));
                        chip.constrain_square_character(ctx, &input, bit, &wrong_root);
                    }
                    1 | 2 => {
                        let wrong_inverse = fp2.load_private(ctx, Fq2::ONE);
                        chip.constrain_inverse(ctx, &input, &wrong_inverse);
                    }
                    _ => {
                        let sign = chip.sign(ctx, &input);
                        sign.debug_prank(ctx, Fr::ONE - sign.value());
                    }
                }
            });
        }
    }
}
