use super::{bls_signature::BlsSignatureChip, pairing::PairingChip, FpChip};
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

/// Compatibility entry point for same-message BLS signatures in G1 and keys in G2.
///
/// Delegates to [`BlsSignatureChip`] so both entry points use the same constraints.
/// The supplied generator is fixed in the circuit. The caller must constrain the
/// returned verification bit to one; the same input assumptions and limitations
/// as [`BlsSignatureChip`] apply.
pub struct BlsSignatureChip2<'chip, F: BigPrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: BigPrimeField> BlsSignatureChip2<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip }
    }

    /// Verifies e(sum(signatures), g2) = e(msghash, sum(pubkeys)).
    pub fn bls_signature_verify(
        &self,
        ctx: &mut Context<F>,
        g2: G2Affine,
        signatures: &[G1Affine],
        pubkeys: &[G2Affine],
        msghash: G1Affine,
    ) -> AssignedValue<F> {
        BlsSignatureChip::new(self.fp_chip, self.pairing_chip)
            .bls_signature_verify_2(ctx, g2, signatures, pubkeys, msghash)
    }
}
