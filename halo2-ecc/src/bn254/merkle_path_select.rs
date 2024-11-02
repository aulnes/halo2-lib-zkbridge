#![allow(non_snake_case)]

use halo2_base::utils::BigPrimeField;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::{ AssignedValue, Context};
use crate::bn254::MerkleInfo;



pub struct MerklePathSelectChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
    pub gate_chip: GateChip<F>,
}



impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize> MerklePathSelectChip<'chip, F, T, RATE> {
    
    pub fn new(poseidon_chip: &'chip PoseidonHasher<F, T, RATE>, gate_chip: GateChip<F>) -> Self {
        Self { poseidon_chip, gate_chip }
    }

    pub fn merkle_path_select_verify_one(
        &self,
        ctx: &mut Context<F>,
        root: F,
        merkle_info: MerkleInfo<F>,
    ) -> AssignedValue<F>{

        let MerkleInfo { leaf, stake, path, index } = merkle_info;
        println!("- Merkle: root: {:?}, leaf: {:?}, path: {:?}, index: {:?}", root, leaf, path, index);

        let x = ctx.load_witness(leaf);
        let stake = ctx.load_witness(stake);
        let poseidon =self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &[x,stake]);
        let path = path.iter().map(|x| ctx.load_witness(*x)).collect::<Vec<_>>();
        let intindex:Vec<F> = index.iter().map(|&b| if b { F::from(1) } else { F::from(0) }).collect();
        let index = intindex.iter().map(|x| ctx.load_witness(*x)).collect::<Vec<_>>();
        let mut hash = poseidon;
        println!("- Merkle: hash: {:?}", hash.value());

        for i in 0..path.len() {
            let path_i = path[i];
            let index_i = index[i];

            let left = self.gate_chip.select(ctx, hash, path_i, index_i);
            let right = self.gate_chip.select(ctx, path_i, hash, index_i);
            let inputs = [left, right];



            println!("- Merkle: inputs: {:?}", inputs.iter().map(|x| x.value()).collect::<Vec<_>>());
            let _hash = self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &inputs); 
            hash = _hash;
            println!("- Merkle: hash: {:?}", hash.value());
        }
        let root = ctx.load_witness(root);
        let result = self.gate_chip.is_equal(ctx, hash, root);
        result


    }

    pub fn merkle_path_select_verify_batch(
        &self,
        ctx: &mut Context<F>,
        root: F,
        merkle_infos: &[MerkleInfo<F>],
    ) -> AssignedValue<F> {
        let mut hashes = Vec::new();
        for merkle_info in merkle_infos.iter() {
            let MerkleInfo { leaf, stake, path, index } = merkle_info;
            let x = ctx.load_witness(*leaf);
            // let zero = ctx.load_witness(F::ZERO);
            let stake = ctx.load_witness(*stake);
            let poseidon =self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &[x,stake]);
            let path = path.iter().map(|x| ctx.load_witness(*x)).collect::<Vec<_>>();
            let intindex:Vec<F> = index.iter().map(|&b| if b { F::from(1) } else { F::from(0) }).collect();
            let index = intindex.iter().map(|x| ctx.load_witness(*x)).collect::<Vec<_>>();
            let mut hash = poseidon;
            for i in 0..path.len() {
                let path_i = path[i];
                let index_i = index[i];

                let left = self.gate_chip.select(ctx, hash, path_i, index_i);
                let right = self.gate_chip.select(ctx, path_i, hash, index_i);
                let inputs = [left, right];
                let _hash = self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &inputs); 
                hash = _hash;
            }
            hashes.push(hash);
        }
        let root = ctx.load_witness(root);
        let mut result = self.gate_chip.is_equal(ctx, hashes[0], root);
        for i in 1..hashes.len() {
            let _result = self.gate_chip.is_equal(ctx, hashes[i], root);
            result = self.gate_chip.and(ctx, result, _result);
        }
        result
        
    }
} 

