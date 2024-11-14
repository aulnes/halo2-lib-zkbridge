#![allow(non_snake_case)]

use halo2_base::utils::BigPrimeField;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::gates::{GateChip, GateInstructions};
// use super::FpChip;
use halo2_base::{ AssignedValue, Context};

pub struct MerkleRootChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
    pub gate_chip: GateChip<F>,
}

impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize> MerkleRootChip<'chip, F, T, RATE> {

    pub fn new(poseidon_chip: &'chip PoseidonHasher<F, T, RATE>, gate_chip: GateChip<F>) -> Self {
        Self { poseidon_chip, gate_chip }
    }

    pub fn merkle_root_verify_layer(
        &self,
        ctx: &mut Context<F>,
        leaves: Vec<AssignedValue<F>>,
    ) -> Vec<AssignedValue<F>>{

        let len = leaves.len();

        let mut next_layer = Vec::new();

        for i in 0..len/2{
            let left = leaves[2*i];
            let right = leaves[2*i+1];

            let hash = self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &[left,right]);

            next_layer.push(hash);
        }

        next_layer

    }

    pub fn merkle_root_verify(
        &self,
        ctx: &mut Context<F>,
        root: F,
        leaves: Vec<F>,
    ) -> AssignedValue<F> {

        let len = leaves.len();
        let depth = len.ilog2();

        let mut layer =  leaves.iter().map(|x| ctx.load_witness(*x)).collect::<Vec<_>>();

        for _ in 0..depth{
            layer = self.merkle_root_verify_layer(ctx, layer.clone());
        }

        let root = ctx.load_witness(root);
        let result = self.gate_chip.is_equal(ctx, layer[0], root);
        result

    }


}