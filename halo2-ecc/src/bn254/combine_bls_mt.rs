#![allow(non_snake_case)]

// use halo2_base::halo2_proofs::halo2curves::bn256::G2Affine;
// use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
// use halo2_base::utils::{BigPrimeField, ScalarField};
// use halo2_base::{AssignedValue, Context};
// use halo2_base::poseidon::hasher::PoseidonHasher;
// use halo2_base::poseidon::{PoseidonChip, PoseidonInstructions};
// use halo2_base::safe_types::FixLenBytes;
// use halo2_base::gates::{GateChip, GateInstructions};
// use halo2_base::halo2_proofs::halo2curves::bn256::G1Affine;
// use super::FpChip;
// use crate::ecc::EccChip;

use halo2_base::utils::BigPrimeField;
use halo2_base::gates::GateInstructions;
// use super::FpChip;
use halo2_base::{ AssignedValue, Context};

use crate::bn254::bls_signature::BlsSignatureChip;
use crate::bn254::merkle_tree::MerkleTreeChip;
use crate::halo2curves::bn256::G1Affine;
use super::MerkleInfo;
use halo2_base::halo2_proofs::halo2curves::bn256::G2Affine;

// pub struct MerkleTreeChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
//     pub fp_chip: &'chip FpChip<'chip, F>,
//     pub poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
// }

pub struct CombineBlsMtChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub bls_chip: &'chip BlsSignatureChip<'chip, F>,
    pub merkle_chip: MerkleTreeChip<'chip, F, T, RATE>,
}



impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize> CombineBlsMtChip<'chip, F, T, RATE> {
    
        pub fn new(bls_chip: &'chip BlsSignatureChip<'chip, F>, merkle_chip: MerkleTreeChip<'chip, F, T, RATE>) -> Self {
            Self { bls_chip, merkle_chip }
        }
    
        pub fn combine_bls_mt_verify(
            &self,
            ctx: &mut Context<F>,
            root: F,
            merkle_infos: &[MerkleInfo<F>],
            g1: G1Affine,
            signatures: &[G2Affine],
            pubkeys: &[G1Affine],
            msghash: G2Affine,
        ) -> AssignedValue<F> {
            // let x = F::from(0);
            assert!(merkle_infos.len() == pubkeys.len(), "merkle_info and pubkeys must be the same length");

            // Verify BLS signature
            let result_bls = self.bls_chip.bls_signature_verify(ctx, g1, signatures, pubkeys, msghash);
            // Verify Merkle tree
            let result_mt = self.merkle_chip.merkle_tree_verify_batch(ctx, root, merkle_infos);
            
            // Combine the results

            let mut result = self.merkle_chip.gate_chip.and(ctx, result_bls, result_mt);



            // 要求pubkeys的x和merkle_info的leaf相等
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
