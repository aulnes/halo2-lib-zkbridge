#![allow(non_snake_case)]

use crate::bigint::ProperCrtUint;
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

use super::bls_signature::AssignedG2;
use super::coordinate_tag::{assigned_coordinate_tag, native_coordinate_tag};
use super::native_integer::{canonical_uint, less_than_or_equal};
use super::point_encoding::{assigned_g2_encoding, native_g2_encoding};
use super::FpChip;

/// Mithril's lottery separator, interpreted as the integer 3 + 3 * 2^64.
/// The BN254 implementation retains its own field, curve and Poseidon suite.
pub fn lottery_domain_separator<F: BigPrimeField>() -> F {
    F::from_u128(3 + (3u128 << 64))
}

/// Native fixture helper for the default Poseidon width 3/rate 2, 8 full and
/// 57 partial rounds. `message_digest` is already a native-field digest; this
/// inner component does not hash raw message bytes with SHA-256.
pub fn native_lottery_prefix<F: BigPrimeField>(root: F, message_digest: F) -> F {
    let mut sponge = poseidon::Poseidon::<F, 3, 2>::new(8, 57);
    sponge.update(&[lottery_domain_separator::<F>(), root, message_digest]);
    sponge.squeeze()
}

/// The default-suite lottery hash with a prefix shared by every vote. Full
/// canonical G2 coordinates replace the legacy lossy x.c0 native-field tag.
pub fn native_lottery_hash_from_prefix<F: BigPrimeField>(
    prefix: F,
    signature: &G2Affine,
    index: F,
) -> F {
    let mut inputs = Vec::with_capacity(18);
    inputs.push(prefix);
    inputs.extend(native_g2_encoding::<F>(signature));
    inputs.push(index);
    let mut sponge = poseidon::Poseidon::<F, 3, 2>::new(8, 57);
    sponge.update(&inputs);
    sponge.squeeze()
}

pub struct EligibilityCheckChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
    pub gate_chip: GateChip<F>,
    pub fp_chip: &'chip FpChip<'chip, F>,
}

impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize>
    EligibilityCheckChip<'chip, F, T, RATE>
{
    pub fn new(
        poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
        gate_chip: GateChip<F>,
        fp_chip: &'chip FpChip<'chip, F>,
    ) -> Self {
        Self { poseidon_chip, gate_chip, fp_chip }
    }

    /// Shared digest-path prefix: Poseidon(DST_LOTTERY, registry root, digest).
    /// A composed certificate must expose/reuse these same root and digest
    /// cells in its public statement and message-to-curve calculation.
    pub fn lottery_prefix_assigned(
        &self,
        ctx: &mut Context<F>,
        root: AssignedValue<F>,
        message_digest: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let domain = ctx.load_constant(lottery_domain_separator::<F>());
        self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &[domain, root, message_digest])
    }

    /// Hashes a complete, canonically encoded signature with the shared prefix
    /// and index. Curve/subgroup membership and the signature equation remain
    /// the enclosing circuit's responsibility.
    pub fn lottery_hash_from_prefix_assigned(
        &self,
        ctx: &mut Context<F>,
        prefix: AssignedValue<F>,
        signature: &AssignedG2<F>,
        index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let signature_encoding = assigned_g2_encoding(ctx, self.fp_chip, signature);
        let mut inputs = Vec::with_capacity(18);
        inputs.push(prefix);
        inputs.extend(signature_encoding);
        inputs.push(index);
        self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &inputs)
    }

    /// Checks the canonical integer lottery hash <= target. The supplied
    /// prefix must be the result of `lottery_prefix_assigned` for the same
    /// public root/digest used elsewhere in the certificate. Target membership
    /// and index bounds/distinctness are separate certificate constraints.
    pub fn eligibility_check_from_prefix_assigned(
        &self,
        ctx: &mut Context<F>,
        target: AssignedValue<F>,
        prefix: AssignedValue<F>,
        signature: &AssignedG2<F>,
        index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let ev = self.lottery_hash_from_prefix_assigned(ctx, prefix, signature, index);
        let ev = canonical_uint(ctx, self.fp_chip.range(), ev);
        let target = canonical_uint(ctx, self.fp_chip.range(), target);
        less_than_or_equal(ctx, self.fp_chip.range(), &ev, &target)
    }

    /// Convenience adapter for one vote receiving an already hashed message
    /// digest rather than a message curve point or the original message bytes.
    pub fn eligibility_check_digest_assigned(
        &self,
        ctx: &mut Context<F>,
        target: AssignedValue<F>,
        root: AssignedValue<F>,
        message_digest: AssignedValue<F>,
        signature: &AssignedG2<F>,
        index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let prefix = self.lottery_prefix_assigned(ctx, root, message_digest);
        self.eligibility_check_from_prefix_assigned(ctx, target, prefix, signature, index)
    }

    /// Checks votes with one prefix derived in-circuit from the shared root
    /// and digest. An empty batch returns true (a conjunction); a certificate
    /// must separately enforce its required nonzero quorum.
    pub fn eligibility_check_digest_batch_assigned(
        &self,
        ctx: &mut Context<F>,
        targets: &[AssignedValue<F>],
        root: AssignedValue<F>,
        message_digest: AssignedValue<F>,
        signatures: &[AssignedG2<F>],
        indexes: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        assert_eq!(targets.len(), signatures.len(), "one signature per target");
        assert_eq!(targets.len(), indexes.len(), "one index per target");
        let prefix = self.lottery_prefix_assigned(ctx, root, message_digest);
        let mut all = ctx.load_constant(F::ONE);
        for ((&target, signature), &index) in targets.iter().zip(signatures).zip(indexes) {
            let result =
                self.eligibility_check_from_prefix_assigned(ctx, target, prefix, signature, index);
            all = self.gate_chip.and(ctx, all, result);
        }
        all
    }

    /// Legacy tag-based component: returns whether the canonical integer hash
    /// is at most the target. New message-alignment callers should use the
    /// digest/prefix APIs above; this historical transcript remains unchanged.
    ///
    /// This component hashes the prototype's native-field tags; it does not
    /// verify a signature or bind a target to a stake/registry entry. Callers
    /// composing a protocol must supply the corresponding constrained cells.
    pub fn eligibility_check_assigned(
        &self,
        ctx: &mut Context<F>,
        phi_stake: AssignedValue<F>,
        signature_tag: AssignedValue<F>,
        message_tag: AssignedValue<F>,
        index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        // The prototype's domain separator is part of the circuit, not a
        // prover-controlled witness.
        let padding = ctx.load_constant(F::ONE);
        let inputs = [padding, message_tag, index, signature_tag];
        let ev = self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &inputs);
        let ev = canonical_uint(ctx, self.fp_chip.range(), ev);
        let target = canonical_uint(ctx, self.fp_chip.range(), phi_stake);
        less_than_or_equal(ctx, self.fp_chip.range(), &ev, &target)
    }

    /// Checks eligibility using already assigned canonical Fq coordinates.
    /// The shared coordinate-tag convention reduces each x.c0 modulo F while
    /// preserving its constraint link to the complete Fq coordinate.
    /// This method does not check curve membership or signature validity.
    pub fn eligibility_check_coordinates_assigned(
        &self,
        ctx: &mut Context<F>,
        phi_stake: AssignedValue<F>,
        signature_x_c0: &ProperCrtUint<F>,
        message_x_c0: &ProperCrtUint<F>,
        index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let signature_tag = assigned_coordinate_tag(ctx, self.fp_chip, signature_x_c0);
        let message_tag = assigned_coordinate_tag(ctx, self.fp_chip, message_x_c0);
        self.eligibility_check_assigned(ctx, phi_stake, signature_tag, message_tag, index)
    }

    /// Adapter for points already assigned by an enclosing curve circuit.
    /// Only the two x.c0 coordinates are used here. Point validation and the
    /// signature equation remain the enclosing circuit's responsibility.
    pub fn eligibility_check_points_assigned(
        &self,
        ctx: &mut Context<F>,
        phi_stake: AssignedValue<F>,
        signature: &AssignedG2<F>,
        msghash: &AssignedG2<F>,
        index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        self.eligibility_check_coordinates_assigned(
            ctx,
            phi_stake,
            &signature.x[0],
            &msghash.x[0],
            index,
        )
    }

    /// Native fixture adapter using canonical Fq x.c0 reduced modulo F, as in
    /// MSP. Values below the native modulus retain their old tags. This is not
    /// a complete or injective G2 encoding, nor an in-circuit point validation.
    pub fn eligibility_check_one(
        &self,
        ctx: &mut Context<F>,
        phi_stake: F,
        signature: G2Affine,
        msghash: G2Affine,
        index: F,
    ) -> AssignedValue<F> {
        let signature = ctx.load_witness(native_coordinate_tag::<F>(&signature.x.c0));
        let message = ctx.load_witness(native_coordinate_tag::<F>(&msghash.x.c0));
        let index = ctx.load_witness(index);
        let target = ctx.load_witness(phi_stake);
        self.eligibility_check_assigned(ctx, target, signature, message, index)
    }

    /// Checks a batch with one shared, constrained message tag.
    pub fn eligibility_check_batch_assigned(
        &self,
        ctx: &mut Context<F>,
        phi_stakes: &[AssignedValue<F>],
        signature_tags: &[AssignedValue<F>],
        message_tag: AssignedValue<F>,
        indexes: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        assert_eq!(phi_stakes.len(), signature_tags.len(), "one signature per target");
        assert_eq!(phi_stakes.len(), indexes.len(), "one index per target");
        let mut all_one = ctx.load_constant(F::ONE);
        for ((&target, &signature), &index) in phi_stakes.iter().zip(signature_tags).zip(indexes) {
            let result =
                self.eligibility_check_assigned(ctx, target, signature, message_tag, index);
            all_one = self.gate_chip.and(ctx, all_one, result);
        }
        all_one
    }

    pub fn eligibility_check_batch(
        &self,
        ctx: &mut Context<F>,
        phi_stakes: &[F],
        signatures: &[G2Affine],
        msghash: G2Affine,
        indexes: &[F],
    ) -> AssignedValue<F> {
        let message = ctx.load_witness(native_coordinate_tag::<F>(&msghash.x.c0));
        let targets = phi_stakes.iter().map(|&value| ctx.load_witness(value)).collect::<Vec<_>>();
        let signatures = signatures
            .iter()
            .map(|signature| ctx.load_witness(native_coordinate_tag::<F>(&signature.x.c0)))
            .collect::<Vec<_>>();
        let indexes = indexes.iter().map(|&value| ctx.load_witness(value)).collect::<Vec<_>>();
        self.eligibility_check_batch_assigned(ctx, &targets, &signatures, message, &indexes)
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;
    use crate::bn254::pairing::PairingChip;
    use halo2_base::{
        gates::RangeInstructions,
        halo2_proofs::halo2curves::{bn256::Fr, ff::Field},
        poseidon::hasher::spec::OptimizedPoseidonSpec,
        utils::testing::base_test,
    };

    #[test]
    fn alignment_regression_lottery_native_and_assigned_transcripts() {
        let root = Fr::from(17);
        let digest = Fr::from(29);
        let signature = G2Affine::from(G2Affine::generator() * Fr::from(7));
        let index = Fr::from(3);
        let prefix = native_lottery_prefix(root, digest);
        let hash = native_lottery_hash_from_prefix(prefix, &signature, index);
        assert_eq!(lottery_domain_separator::<Fr>(), Fr::from_raw([3, 3, 0, 0]));
        base_test().k(13).lookup_bits(8).run(|ctx, range| {
            let fp = FpChip::<Fr>::new(range, 90, 3);
            let mut poseidon =
                PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
            let gate = GateChip::default();
            poseidon.initialize_consts(ctx, &gate);
            let lottery = EligibilityCheckChip::new(&poseidon, gate, &fp);
            let assigned_root = ctx.load_witness(root);
            let assigned_digest = ctx.load_witness(digest);
            let assigned_index = ctx.load_witness(index);
            let signature = PairingChip::new(&fp).load_private_g2(ctx, signature);
            let prefix_cell = lottery.lottery_prefix_assigned(ctx, assigned_root, assigned_digest);
            let hash_cell = lottery.lottery_hash_from_prefix_assigned(
                ctx,
                prefix_cell,
                &signature,
                assigned_index,
            );
            range.gate().assert_is_const(ctx, &prefix_cell, &prefix);
            range.gate().assert_is_const(ctx, &hash_cell, &hash);
        });
    }

    #[test]
    fn alignment_regression_lottery_binds_root_digest_signature_and_index() {
        let root = Fr::from(17);
        let digest = Fr::from(29);
        let signature = G2Affine::from(G2Affine::generator() * Fr::from(7));
        let index = Fr::from(3);
        let expected =
            native_lottery_hash_from_prefix(native_lottery_prefix(root, digest), &signature, index);
        // In particular sigma and -sigma have identical x.c0 tags. The new
        // transcript must still bind the signature's y coordinates.
        let cases = [
            (root + Fr::ONE, digest, signature, index),
            (root, digest + Fr::ONE, signature, index),
            (root, digest, -signature, index),
            (root, digest, signature, index + Fr::ONE),
        ];
        for (root, digest, signature, index) in cases {
            assert_ne!(
                native_lottery_hash_from_prefix(
                    native_lottery_prefix(root, digest),
                    &signature,
                    index
                ),
                expected
            );
            base_test().k(13).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                let mut poseidon =
                    PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
                let gate = GateChip::default();
                poseidon.initialize_consts(ctx, &gate);
                let lottery = EligibilityCheckChip::new(&poseidon, gate, &fp);
                let root = ctx.load_witness(root);
                let digest = ctx.load_witness(digest);
                let index = ctx.load_witness(index);
                let signature = PairingChip::new(&fp).load_private_g2(ctx, signature);
                let prefix = lottery.lottery_prefix_assigned(ctx, root, digest);
                let hash =
                    lottery.lottery_hash_from_prefix_assigned(ctx, prefix, &signature, index);
                range.gate().assert_is_const(ctx, &hash, &expected);
            });
        }
    }

    #[test]
    fn alignment_regression_lottery_canonical_threshold_boundary() {
        let root = Fr::from(17);
        let digest = Fr::from(29);
        let signature = G2Affine::from(G2Affine::generator() * Fr::from(7));
        let index = Fr::from(3);
        let ev =
            native_lottery_hash_from_prefix(native_lottery_prefix(root, digest), &signature, index);
        assert_ne!(ev, Fr::ZERO);
        for (target, expected) in [(ev, Fr::ONE), (ev - Fr::ONE, Fr::ZERO), (-Fr::ONE, Fr::ONE)] {
            base_test().k(13).lookup_bits(8).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                let mut poseidon =
                    PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
                let gate = GateChip::default();
                poseidon.initialize_consts(ctx, &gate);
                let lottery = EligibilityCheckChip::new(&poseidon, gate, &fp);
                let root = ctx.load_witness(root);
                let digest = ctx.load_witness(digest);
                let index = ctx.load_witness(index);
                let target = ctx.load_witness(target);
                let signature = PairingChip::new(&fp).load_private_g2(ctx, signature);
                let flag = lottery.eligibility_check_digest_assigned(
                    ctx, target, root, digest, &signature, index,
                );
                range.gate().assert_is_const(ctx, &flag, &expected);
            });
        }
    }

    #[test]
    fn alignment_regression_lottery_batch_checks_every_vote() {
        let root = Fr::from(17);
        let digest = Fr::from(29);
        let signatures =
            [G2Affine::generator(), G2Affine::from(G2Affine::generator() * Fr::from(7))];
        let indexes = [Fr::from(3), Fr::from(5)];
        let prefix = native_lottery_prefix(root, digest);
        let targets = [
            native_lottery_hash_from_prefix(prefix, &signatures[0], indexes[0]),
            native_lottery_hash_from_prefix(prefix, &signatures[1], indexes[1]),
        ];
        assert_ne!(targets[1], Fr::ZERO);
        for valid in [true, false] {
            base_test().k(14).lookup_bits(8).run(|ctx, range| {
                let fp = FpChip::<Fr>::new(range, 90, 3);
                let mut poseidon =
                    PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
                let gate = GateChip::default();
                poseidon.initialize_consts(ctx, &gate);
                let lottery = EligibilityCheckChip::new(&poseidon, gate, &fp);
                let root = ctx.load_witness(root);
                let digest = ctx.load_witness(digest);
                let indexes = indexes.map(|value| ctx.load_witness(value));
                let mut target_values = targets;
                if !valid {
                    target_values[1] -= Fr::ONE;
                }
                let targets = target_values.map(|value| ctx.load_witness(value));
                let signatures =
                    signatures.map(|point| PairingChip::new(&fp).load_private_g2(ctx, point));
                let flag = lottery.eligibility_check_digest_batch_assigned(
                    ctx,
                    &targets,
                    root,
                    digest,
                    &signatures,
                    &indexes,
                );
                range.gate().assert_is_const(ctx, &flag, &Fr::from(valid as u64));
            });
        }
    }
}
