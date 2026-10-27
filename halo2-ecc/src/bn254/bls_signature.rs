#![allow(non_snake_case)]

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip, FpPoint, FqPoint};
use crate::ecc::{EcPoint, EccChip};
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bn256::{Fq12, G1Affine, G2Affine};
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

pub type AssignedG1<F> = EcPoint<F, FpPoint<F>>;
pub type AssignedG2<F> = EcPoint<F, FqPoint<F>>;

/// Arithmetic for same-message aggregate BLS pairing equations on prehashed points.
///
/// This chip does not implement hash-to-curve, proof of possession, or a G2
/// subgroup check. Callers must constrain the returned verification bit to one
/// and bind the assigned inputs to their intended statement.
pub struct BlsSignatureChip<'chip, F: BigPrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: BigPrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip }
    }

    /// Native-input convenience wrapper. The generator is fixed in the circuit;
    /// signatures, keys, and the prehashed message are private witnesses.
    pub fn bls_signature_verify(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signatures: &[G2Affine],
        pubkeys: &[G1Affine],
        msghash: G2Affine,
    ) -> AssignedValue<F> {
        let g1_chip = EccChip::new(self.fp_chip);
        let generator = g1_chip.assign_constant_point(ctx, g1);
        let message = self.pairing_chip.load_private_g2(ctx, msghash);
        let signatures = signatures
            .iter()
            .map(|p| self.pairing_chip.load_private_g2(ctx, *p))
            .collect::<Vec<_>>();
        let pubkeys =
            pubkeys.iter().map(|p| self.pairing_chip.load_private_g1(ctx, *p)).collect::<Vec<_>>();
        self.bls_signature_verify_assigned(ctx, &generator, &signatures, &pubkeys, &message)
    }

    /// Verifies e(g1, sum(signatures)) = e(sum(pubkeys), msghash) using the
    /// supplied cells, so an enclosing circuit can reuse and bind those cells.
    /// Inputs must already have been constrained to be valid nonidentity points.
    pub fn bls_signature_verify_assigned(
        &self,
        ctx: &mut Context<F>,
        g1: &AssignedG1<F>,
        signatures: &[AssignedG2<F>],
        pubkeys: &[AssignedG1<F>],
        msghash: &AssignedG2<F>,
    ) -> AssignedValue<F> {
        assert_eq!(
            signatures.len(),
            pubkeys.len(),
            "signatures and pubkeys must be the same length"
        );
        assert!(!signatures.is_empty(), "signatures must not be empty");
        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let signature = g2_chip.sum::<G2Affine>(ctx, signatures.to_vec());
        let pubkey = g1_chip.sum::<G1Affine>(ctx, pubkeys.to_vec());
        let neg_signature = g2_chip.negate(ctx, &signature);
        let paired = self
            .pairing_chip
            .multi_miller_loop(ctx, vec![(g1, &neg_signature), (&pubkey, msghash)]);
        let fp12_chip = Fp12Chip::new(self.fp_chip);
        let result = fp12_chip.final_exp(ctx, paired);
        let one = fp12_chip.load_constant(ctx, Fq12::one());
        fp12_chip.is_equal(ctx, result, one)
    }

    /// Native-input wrapper for signatures in G1 and public keys in G2.
    pub fn bls_signature_verify_2(
        &self,
        ctx: &mut Context<F>,
        g2: G2Affine,
        signatures: &[G1Affine],
        pubkeys: &[G2Affine],
        msghash: G1Affine,
    ) -> AssignedValue<F> {
        let fp2_chip = Fp2Chip::new(self.fp_chip);
        let generator = EccChip::new(&fp2_chip).assign_constant_point(ctx, g2);
        let message = self.pairing_chip.load_private_g1(ctx, msghash);
        let signatures = signatures
            .iter()
            .map(|p| self.pairing_chip.load_private_g1(ctx, *p))
            .collect::<Vec<_>>();
        let pubkeys =
            pubkeys.iter().map(|p| self.pairing_chip.load_private_g2(ctx, *p)).collect::<Vec<_>>();
        self.bls_signature_verify_2_assigned(ctx, &generator, &signatures, &pubkeys, &message)
    }

    /// Verifies e(sum(signatures), g2) = e(msghash, sum(pubkeys)).
    /// Inputs must already have been constrained to be valid nonidentity points.
    pub fn bls_signature_verify_2_assigned(
        &self,
        ctx: &mut Context<F>,
        g2: &AssignedG2<F>,
        signatures: &[AssignedG1<F>],
        pubkeys: &[AssignedG2<F>],
        msghash: &AssignedG1<F>,
    ) -> AssignedValue<F> {
        assert_eq!(
            signatures.len(),
            pubkeys.len(),
            "signatures and pubkeys must be the same length"
        );
        assert!(!signatures.is_empty(), "signatures must not be empty");
        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let signature = g1_chip.sum::<G1Affine>(ctx, signatures.to_vec());
        let pubkey = g2_chip.sum::<G2Affine>(ctx, pubkeys.to_vec());
        let neg_pubkey = g2_chip.negate(ctx, &pubkey);
        let paired = self
            .pairing_chip
            .multi_miller_loop(ctx, vec![(&signature, g2), (msghash, &neg_pubkey)]);
        let fp12_chip = Fp12Chip::new(self.fp_chip);
        let result = fp12_chip.final_exp(ctx, paired);
        let one = fp12_chip.load_constant(ctx, Fq12::one());
        fp12_chip.is_equal(ctx, result, one)
    }
}
