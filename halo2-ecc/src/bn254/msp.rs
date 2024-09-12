#![allow(non_snake_case)]

use super::bls_signature::BlsSignatureChip;
use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip};
use crate::bigint::ProperCrtUint;
use crate::ecc::{scalar_multiply, EcPoint, EccChip};
use crate::fields::vector::{FieldVector};
use crate::fields::{fp, fp12, fp2, FieldChip};
use crate::halo2_proofs::halo2curves::bn256::Fq12;
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::gates::{GateChip,GateInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq, Fq2};
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows
pub struct MspChip<'chip, F: BigPrimeField> {
    pub bls_signature_chip: &'chip BlsSignatureChip<'chip, F>,
    pub poseidon_chip: &'chip PoseidonHasher<F, 3, 2>,
    // pub fp_chip: &'chip FpChip<'chip, F>,
}

impl<'chip, F: BigPrimeField> MspChip<'chip, F> {
    pub fn new(
        bls_signature_chip: &'chip BlsSignatureChip<F>,
        poseidon_chip: &'chip PoseidonHasher<F, 3, 2>,
        // fp_chip: &'chip FpChip<F>,
    ) -> Self {
        Self {
            bls_signature_chip,
            poseidon_chip,
            // fp_chip,
        }
    }

    pub fn msp_verify(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signatures: &[G2Affine],
        pubkeys: &[G1Affine], // mvk
        msghash: G2Affine,
        weighting_seed : F,
        ivk: G1Affine,
        isig: G2Affine, // \mu
    ) -> AssignedValue<F> {
        // TODO: verify proof of possesion

        // A: verify BLS signature
        let verify_A = self.bls_signature_chip.bls_signature_verify(ctx, g1, signatures, pubkeys, msghash);


        // B
        let signatures_x_assigned = signatures.iter().map(|pt| {
            ctx.load_witness(F::from_bytes_le(&pt.x.c0.to_bytes()))
        }).collect::<Vec<_>>();
        let gate_chip = GateChip::<F>::default();
        let weighting_seed_comp = self.poseidon_chip.hash_fix_len_array(ctx, &gate_chip, &signatures_x_assigned[..]);
        let weighting_seed_assigned = ctx.load_witness(weighting_seed);
        // B_1 : verify weighting seed
        let verify_B_1 = gate_chip.is_equal(ctx, weighting_seed_assigned, weighting_seed_comp);
        // e_i = H(i,weighting_seed) for i in 0..n where n is the number of public keys
        let e_is  = pubkeys.iter().enumerate().map(|(i, _)| {
            let i_assigned = ctx.load_witness(F::from(i as u64));
            self.poseidon_chip.hash_fix_len_array(ctx, &gate_chip, &[i_assigned, weighting_seed_assigned])
        }).collect::<Vec<_>>();

        let g1_chip = EccChip::new(self.bls_signature_chip.fp_chip);
        let fp2_chip = Fp2Chip::new(self.bls_signature_chip.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        // B_2 : verify ivk, isig
        // ivk = \sum_{i=0}^{n-1} e_i * mvk_i
        let ivk_assigned = self.bls_signature_chip.pairing_chip.load_private_g1(ctx, ivk);
        let mvks = pubkeys.iter().map(|pt| self.bls_signature_chip.pairing_chip.load_private_g1(ctx, *pt)).collect::<Vec<_>>();
        let products = mvks.iter().zip(e_is.iter()).map(|(mvk, e_i)| {
            g1_chip.scalar_mult::<G1Affine>(ctx, mvk.clone(), e_is.clone(),254,2)
        }).collect::<Vec<_>>();


        let ivk_comp = g1_chip.sum::<G1Affine>(ctx, products);
        let verify_B_2 = g1_chip.is_equal(ctx, ivk_assigned, ivk_comp);
       
        // isig = \sum_{i=0}^{n-1} e_i * sig_i
        let isig_assigned = self.bls_signature_chip.pairing_chip.load_private_g2(ctx, isig);
        let sigs = signatures.iter().map(|pt| self.bls_signature_chip.pairing_chip.load_private_g2(ctx, *pt)).collect::<Vec<_>>();
        let products = sigs.iter().zip(e_is.iter()).map(|(sig, e_i)| {
            g2_chip.scalar_mult::<G2Affine>(ctx, sig.clone(), e_is.clone(),254,2)
        }).collect::<Vec<_>>();
        let isig_comp = g2_chip.sum::<G2Affine>(ctx, products);
        let verify_B_3 = g2_chip.is_equal(ctx, isig_assigned, isig_comp);
        

        // B_4 : verify e(g1, isig) = e(ivk, H(m))
        let verify_B_4 = self.bls_signature_chip.bls_signature_verify(ctx, g1, &[isig], &[ivk], msghash);

        println!("verify_A: {:?}", verify_A);
        println!("verify_B_1: {:?}", verify_B_1);
        println!("verify_B_2: {:?}", verify_B_2);
        println!("verify_B_3: {:?}", verify_B_3);
        println!("verify_B_4: {:?}", verify_B_4);
        // Final result
        let result1 = gate_chip.and(ctx, verify_A, verify_B_1);
        println!("result1: {:?}", result1);
        let result2 = gate_chip.and(ctx, verify_B_2, verify_B_3);
        println!("result2: {:?}", result2);
        let result = gate_chip.and(ctx, result1, result2);
        println!("result: {:?}", result);
        let result = gate_chip.and(ctx, result, verify_B_4);
        println!("result: {:?}", result);
    
        result
        

    }
}
