#![allow(non_snake_case)]

use super::bls_signature::{AssignedG1, AssignedG2, BlsSignatureChip};
use super::coordinate_tag::assigned_coordinate_tag;
use super::Fp2Chip;
use crate::bigint::ProperCrtUint;
use crate::ecc::EccChip;
use crate::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

/// MSP arithmetic component, with the prototype's x-coordinate seed projection.
/// This is not a full STMS verifier: see the prehashed BLS chip's preconditions.
pub struct MspChip<'chip, F: BigPrimeField> {
    pub bls_signature_chip: &'chip BlsSignatureChip<'chip, F>,
    pub poseidon_chip: &'chip PoseidonHasher<F, 3, 2>,
}

impl<'chip> MspChip<'chip, Fr> {
    /// Digest-input MSP: derive the shared message point inside the circuit.
    ///
    /// `root` and `message_digest` are native field elements, as at the input
    /// boundary of Mithril's inner Certificate circuit. The enclosing circuit
    /// must expose these SAME cells as public instances. Raw-message SHA-256,
    /// registry membership, threshold authentication and quorum are separate
    /// relations; this method does not turn MSP into a complete certificate.
    ///
    /// Assigned points retain the prehashed API's valid, nonidentity, subgroup
    /// input preconditions. The derived message itself is cofactor-cleared.
    /// The caller must constrain the returned acceptance bit to one.
    pub fn msp_verify_msm_digest_assigned(
        &self,
        pool: &mut SinglePhaseCoreManager<Fr>,
        root: AssignedValue<Fr>,
        message_digest: AssignedValue<Fr>,
        signatures: &[AssignedG2<Fr>],
        pubkeys: &[AssignedG1<Fr>],
        weighting_seed: AssignedValue<Fr>,
        ivk: &AssignedG1<Fr>,
        isig: &AssignedG2<Fr>,
    ) -> AssignedValue<Fr> {
        let ctx = pool.main();
        let message = super::message_hash::MessageHashChip::new(
            self.bls_signature_chip.fp_chip,
            self.poseidon_chip,
        )
        .hash_assigned(ctx, root, message_digest);
        let generator = EccChip::new(self.bls_signature_chip.fp_chip)
            .assign_constant_point(ctx, G1Affine::generator());
        self.msp_verify_msm_assigned(
            pool,
            &generator,
            signatures,
            pubkeys,
            &message,
            weighting_seed,
            ivk,
            isig,
        )
    }
}

impl<'chip, F: BigPrimeField> MspChip<'chip, F> {
    pub fn new(
        bls_signature_chip: &'chip BlsSignatureChip<F>,
        poseidon_chip: &'chip PoseidonHasher<F, 3, 2>,
    ) -> Self {
        Self { bls_signature_chip, poseidon_chip }
    }

    /// Hash canonical assigned x (or x.c0) coordinates, reduced into F through
    /// their constrained CRT native cells, using the same coordinate-tag
    /// convention as eligibility. All projections reuse assigned cells.
    /// It is not an injective encoding of an entire curve point.
    fn weights(
        &self,
        ctx: &mut Context<F>,
        coordinates: impl IntoIterator<Item = ProperCrtUint<F>>,
        weighting_seed: AssignedValue<F>,
    ) -> (Vec<Vec<AssignedValue<F>>>, AssignedValue<F>) {
        let coordinates = coordinates
            .into_iter()
            .map(|x| assigned_coordinate_tag(ctx, self.bls_signature_chip.fp_chip, &x))
            .collect::<Vec<_>>();
        let gate = GateChip::default();
        let seed = self.poseidon_chip.hash_fix_len_array(ctx, &gate, &coordinates);
        let seed_ok = gate.is_equal(ctx, weighting_seed, seed);
        let weights = (0..coordinates.len())
            .map(|i| {
                // The index is part of the fixed circuit shape, not a free witness.
                let index = ctx.load_constant(F::from(i as u64));
                vec![self.poseidon_chip.hash_fix_len_array(ctx, &gate, &[index, weighting_seed])]
            })
            .collect();
        (weights, seed_ok)
    }

    pub fn msp_verify(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signatures: &[G2Affine],
        pubkeys: &[G1Affine],
        msghash: G2Affine,
        weighting_seed: F,
        ivk: G1Affine,
        isig: G2Affine,
    ) -> AssignedValue<F> {
        let generator =
            EccChip::new(self.bls_signature_chip.fp_chip).assign_constant_point(ctx, g1);
        let pairing = self.bls_signature_chip.pairing_chip;
        let signatures =
            signatures.iter().map(|p| pairing.load_private_g2(ctx, *p)).collect::<Vec<_>>();
        let pubkeys = pubkeys.iter().map(|p| pairing.load_private_g1(ctx, *p)).collect::<Vec<_>>();
        let message = pairing.load_private_g2(ctx, msghash);
        let seed = ctx.load_witness(weighting_seed);
        let ivk = pairing.load_private_g1(ctx, ivk);
        let isig = pairing.load_private_g2(ctx, isig);
        self.msp_verify_assigned(
            ctx,
            &generator,
            &signatures,
            &pubkeys,
            &message,
            seed,
            &ivk,
            &isig,
        )
    }

    /// All checks share the same assigned points. The caller must constrain the
    /// returned bit to one and bind the input cells to its statement.
    pub fn msp_verify_assigned(
        &self,
        ctx: &mut Context<F>,
        g1: &AssignedG1<F>,
        signatures: &[AssignedG2<F>],
        pubkeys: &[AssignedG1<F>],
        msghash: &AssignedG2<F>,
        weighting_seed: AssignedValue<F>,
        ivk: &AssignedG1<F>,
        isig: &AssignedG2<F>,
    ) -> AssignedValue<F> {
        let verify_a = self
            .bls_signature_chip
            .bls_signature_verify_assigned(ctx, g1, signatures, pubkeys, msghash);
        let (weights, seed_ok) =
            self.weights(ctx, signatures.iter().map(|p| p.x[0].clone()), weighting_seed);
        let g1_chip = EccChip::new(self.bls_signature_chip.fp_chip);
        let fp2_chip = Fp2Chip::new(self.bls_signature_chip.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let products = pubkeys
            .iter()
            .zip(&weights)
            .map(|(p, e)| g1_chip.scalar_mult::<G1Affine>(ctx, p.clone(), e.clone(), 254, 4))
            .collect::<Vec<_>>();
        let computed_ivk = g1_chip.sum::<G1Affine>(ctx, products);
        let key_ok = g1_chip.is_equal(ctx, ivk.clone(), computed_ivk);
        let products = signatures
            .iter()
            .zip(&weights)
            .map(|(p, e)| g2_chip.scalar_mult::<G2Affine>(ctx, p.clone(), e.clone(), 254, 4))
            .collect::<Vec<_>>();
        let computed_isig = g2_chip.sum::<G2Affine>(ctx, products);
        let sig_ok = g2_chip.is_equal(ctx, isig.clone(), computed_isig);
        let verify_b = self.bls_signature_chip.bls_signature_verify_assigned(
            ctx,
            g1,
            std::slice::from_ref(isig),
            std::slice::from_ref(ivk),
            msghash,
        );
        self.combine(ctx, [verify_a, seed_ok, key_ok, sig_ok, verify_b])
    }

    pub fn msp_verify_2(
        &self,
        ctx: &mut Context<F>,
        g2: G2Affine,
        signatures: &[G1Affine],
        pubkeys: &[G2Affine],
        msghash: G1Affine,
        weighting_seed: F,
        ivk: G2Affine,
        isig: G1Affine,
    ) -> AssignedValue<F> {
        let fp2_chip = Fp2Chip::new(self.bls_signature_chip.fp_chip);
        let generator = EccChip::new(&fp2_chip).assign_constant_point(ctx, g2);
        let pairing = self.bls_signature_chip.pairing_chip;
        let signatures =
            signatures.iter().map(|p| pairing.load_private_g1(ctx, *p)).collect::<Vec<_>>();
        let pubkeys = pubkeys.iter().map(|p| pairing.load_private_g2(ctx, *p)).collect::<Vec<_>>();
        let message = pairing.load_private_g1(ctx, msghash);
        let seed = ctx.load_witness(weighting_seed);
        let ivk = pairing.load_private_g2(ctx, ivk);
        let isig = pairing.load_private_g1(ctx, isig);
        self.msp_verify_2_assigned(
            ctx,
            &generator,
            &signatures,
            &pubkeys,
            &message,
            seed,
            &ivk,
            &isig,
        )
    }

    pub fn msp_verify_2_assigned(
        &self,
        ctx: &mut Context<F>,
        g2: &AssignedG2<F>,
        signatures: &[AssignedG1<F>],
        pubkeys: &[AssignedG2<F>],
        msghash: &AssignedG1<F>,
        weighting_seed: AssignedValue<F>,
        ivk: &AssignedG2<F>,
        isig: &AssignedG1<F>,
    ) -> AssignedValue<F> {
        let verify_a = self
            .bls_signature_chip
            .bls_signature_verify_2_assigned(ctx, g2, signatures, pubkeys, msghash);
        let (weights, seed_ok) =
            self.weights(ctx, signatures.iter().map(|p| p.x.clone()), weighting_seed);
        let g1_chip = EccChip::new(self.bls_signature_chip.fp_chip);
        let fp2_chip = Fp2Chip::new(self.bls_signature_chip.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let products = pubkeys
            .iter()
            .zip(&weights)
            .map(|(p, e)| g2_chip.scalar_mult::<G2Affine>(ctx, p.clone(), e.clone(), 254, 4))
            .collect::<Vec<_>>();
        let computed_ivk = g2_chip.sum::<G2Affine>(ctx, products);
        let key_ok = g2_chip.is_equal(ctx, ivk.clone(), computed_ivk);
        let products = signatures
            .iter()
            .zip(&weights)
            .map(|(p, e)| g1_chip.scalar_mult::<G1Affine>(ctx, p.clone(), e.clone(), 254, 4))
            .collect::<Vec<_>>();
        let computed_isig = g1_chip.sum::<G1Affine>(ctx, products);
        let sig_ok = g1_chip.is_equal(ctx, isig.clone(), computed_isig);
        let verify_b = self.bls_signature_chip.bls_signature_verify_2_assigned(
            ctx,
            g2,
            std::slice::from_ref(isig),
            std::slice::from_ref(ivk),
            msghash,
        );
        self.combine(ctx, [verify_a, seed_ok, key_ok, sig_ok, verify_b])
    }

    pub fn msp_verify_msm(
        &self,
        pool: &mut SinglePhaseCoreManager<F>,
        g1: G1Affine,
        signatures: &[G2Affine],
        pubkeys: &[G1Affine],
        msghash: G2Affine,
        weighting_seed: F,
        ivk: G1Affine,
        isig: G2Affine,
    ) -> AssignedValue<F> {
        let ctx = pool.main();
        let generator =
            EccChip::new(self.bls_signature_chip.fp_chip).assign_constant_point(ctx, g1);
        let pairing = self.bls_signature_chip.pairing_chip;
        let signatures =
            signatures.iter().map(|p| pairing.load_private_g2(ctx, *p)).collect::<Vec<_>>();
        let pubkeys = pubkeys.iter().map(|p| pairing.load_private_g1(ctx, *p)).collect::<Vec<_>>();
        let message = pairing.load_private_g2(ctx, msghash);
        let seed = ctx.load_witness(weighting_seed);
        let ivk = pairing.load_private_g1(ctx, ivk);
        let isig = pairing.load_private_g2(ctx, isig);
        self.msp_verify_msm_assigned(
            pool,
            &generator,
            &signatures,
            &pubkeys,
            &message,
            seed,
            &ivk,
            &isig,
        )
    }

    pub fn msp_verify_msm_assigned(
        &self,
        pool: &mut SinglePhaseCoreManager<F>,
        g1: &AssignedG1<F>,
        signatures: &[AssignedG2<F>],
        pubkeys: &[AssignedG1<F>],
        msghash: &AssignedG2<F>,
        weighting_seed: AssignedValue<F>,
        ivk: &AssignedG1<F>,
        isig: &AssignedG2<F>,
    ) -> AssignedValue<F> {
        let ctx = pool.main();
        let verify_a = self
            .bls_signature_chip
            .bls_signature_verify_assigned(ctx, g1, signatures, pubkeys, msghash);
        let (weights, seed_ok) =
            self.weights(ctx, signatures.iter().map(|p| p.x[0].clone()), weighting_seed);
        let verify_b = self.bls_signature_chip.bls_signature_verify_assigned(
            ctx,
            g1,
            std::slice::from_ref(isig),
            std::slice::from_ref(ivk),
            msghash,
        );
        let g1_chip = EccChip::new(self.bls_signature_chip.fp_chip);
        let fp2_chip = Fp2Chip::new(self.bls_signature_chip.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let computed_ivk =
            g1_chip.variable_base_msm_custom::<G1Affine>(pool, pubkeys, weights.clone(), 254, 4);
        let computed_isig =
            g2_chip.variable_base_msm_custom::<G2Affine>(pool, signatures, weights, 254, 4);
        let ctx = pool.main();
        let key_ok = g1_chip.is_equal(ctx, ivk.clone(), computed_ivk);
        let sig_ok = g2_chip.is_equal(ctx, isig.clone(), computed_isig);
        self.combine(ctx, [verify_a, seed_ok, key_ok, sig_ok, verify_b])
    }

    fn combine(&self, ctx: &mut Context<F>, checks: [AssignedValue<F>; 5]) -> AssignedValue<F> {
        let gate = GateChip::default();
        checks.into_iter().reduce(|a, b| gate.and(ctx, a, b)).unwrap()
    }
}
