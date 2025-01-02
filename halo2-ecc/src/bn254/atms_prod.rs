#![allow(non_snake_case)]
use halo2_base::gates::GateInstructions;

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip};
use crate::ecc::EccChip;
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bn256::Fq12;
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

use crate::bn254::merkle_path_select::MerklePathSelectChip;
use super::MerkleInfo;
use crate::halo2curves::bn256::Fr;


pub struct ATMSProdChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
    pub merkle_chip: MerklePathSelectChip<'chip, F, T, RATE>,
}

impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize> ATMSProdChip<'chip, F, T, RATE>{

    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip: &'chip PairingChip<F>, merkle_chip: MerklePathSelectChip<'chip, F, T, RATE>) -> Self {
        Self { fp_chip, pairing_chip, merkle_chip }
    }

    pub fn atms_prod_verify(
        &self,
        ctx: &mut Context<F>,
        root: F,
        merkle_infos: &[MerkleInfo<F>],
        g1: G1Affine,
        product: G1Affine, // the product of all public keys
        pubkeys: &[G1Affine],
        message: F,
        signatures: &[G2Affine],
    )-> AssignedValue<F> {

        assert!(merkle_infos.len() == pubkeys.len(), "merkle_info and pubkeys must be the same length");

        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        let g1_assigned = self.pairing_chip.load_private_g1(ctx, g1);

        // assgin message
        let assigned_msg = ctx.load_witness(message);
        let zero = ctx.load_witness(F::ZERO);
        let msghash = self.merkle_chip.poseidon_chip.hash_fix_len_array(ctx, &self.merkle_chip.gate_chip, &[assigned_msg,zero]);
        let msghash_byte:[u8;32] = msghash.value().to_bytes_le().to_vec().try_into().expect("Invalid Fr bytes");
        let msghash = G2Affine::from(G2Affine::generator() * Fr::from_bytes(&msghash_byte).unwrap());
        
        let hash_m_assigned = self.pairing_chip.load_private_g2(ctx, msghash);
        
        // assign signatures
        let signature_points = signatures
            .iter()
            .map(|pt| g2_chip.load_private::<G2Affine>(ctx, (pt.x, pt.y)))
            .collect::<Vec<_>>();
        let signature_agg_assigned = g2_chip.sum::<G2Affine>(ctx, signature_points);


        // assign product of all public keys
        let prod_key = g1_chip.load_private::<G1Affine>(ctx, (product.x,product.y));

        // assign public keys
        let pubkey_points = pubkeys
            .iter()
            .map(|pt| g1_chip.load_private::<G1Affine>(ctx, (pt.x, pt.y)))
            .collect::<Vec<_>>();
        let sub_pk = g1_chip.sum::<G1Affine>(ctx, pubkey_points);

        // compute actual key
        let real_pk = g1_chip.sub_unequal(ctx, prod_key, sub_pk, true);

        // BLS Verify phase ------------------------------------------------
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let g12_chip = EccChip::new(&fp12_chip);
        let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_agg_assigned);

        let multi_paired = self.pairing_chip.multi_miller_loop(
            ctx,
            vec![
                (&g1_assigned, &neg_signature_assigned_g12),
                (&real_pk, &hash_m_assigned),
            ],
        );
        let result = fp12_chip.final_exp(ctx, multi_paired);

        // Check signatures are verified
        let fp12_one = fp12_chip.load_constant(ctx, Fq12::one());
        let result_bls = fp12_chip.is_equal(ctx, result, fp12_one);
        // ----------------------------------------------------------------


        // Merkle path Verify phase
        let result_mt = self.merkle_chip.merkle_path_select_verify_batch(ctx, root, merkle_infos);

        let mut result = self.merkle_chip.gate_chip.and(ctx, result_bls, result_mt);

        // constraint public keys to be equal
        // can be optimized
        for i in 0..pubkeys.len() {
            let leaf = merkle_infos[i].leaf;
            let pk_x = F::from_bytes_le(&pubkeys[i].x.to_bytes());
            
            let leaf = ctx.load_witness(leaf);
            let pk_x = ctx.load_witness(pk_x);

            let _result = self.merkle_chip.gate_chip.is_equal(ctx,pk_x,leaf);
            result = self.merkle_chip.gate_chip.and(ctx, result, _result);
        }
        result
    }


}