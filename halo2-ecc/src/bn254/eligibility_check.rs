#![allow(non_snake_case)]


use halo2_base::utils::BigPrimeField;
use crate::bigint::{big_is_equal, big_less_than};
use crate::fields::FieldChip;
use halo2_base::gates::{GateChip, GateInstructions};
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use crate::bigint::ProperUint;
use super::FpChip;
use halo2_base::{ AssignedValue, Context};
use halo2_base::poseidon::hasher::PoseidonHasher;


pub struct EligibilityCheckChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
    pub gate_chip: GateChip<F>,
    pub fp_chip: &'chip FpChip<'chip, F>,
}


impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize> EligibilityCheckChip<'chip, F, T, RATE>{

    pub fn new(poseidon_chip: &'chip PoseidonHasher<F, T, RATE>, gate_chip: GateChip<F>, fp_chip: &'chip FpChip<'chip, F>) -> Self {
        Self { poseidon_chip, gate_chip, fp_chip }
    }
    
    pub fn eligibility_check_one(
        &self,
        ctx: &mut Context<F>,
        phi_stake: F,
        signature: G2Affine,
        msghash: G2Affine,
        index : F,
    ) -> AssignedValue<F>{

        let signature_assigned = ctx.load_witness(F::from_bytes_le(&signature.x.c0.to_bytes()));

        let msg_hash_assigned = ctx.load_witness(F::from_bytes_le(&msghash.x.c0.to_bytes()));

        let index_assigned = ctx.load_witness(index);

        // This is a padding on the first palce
        // "map" string, but for test we just use 1
        let padding = F::from(0x1);

        let padding_assigned = ctx.load_witness(padding);

        let inputs = [
            padding_assigned,
            msg_hash_assigned,
            index_assigned,
            signature_assigned
        ];

        let ev_assigned =self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &inputs);

        let phi_stake_assigned = ctx.load_witness(phi_stake);

        let base_chip = self.fp_chip;

        let ev_pint = ProperUint(vec![ev_assigned]);
        let phi_stake_pint = ProperUint(vec![phi_stake_assigned]);

        let less = big_less_than::assign(
            base_chip.range(), 
            ctx, 
            ev_pint.clone(),
            phi_stake_pint.clone(),
            base_chip.limb_bits,
            base_chip.limb_bases[1],
        );

        let equal = big_is_equal::assign(
            base_chip.gate(), 
            ctx, 
            ev_pint,
            phi_stake_pint,
        );

        let result = base_chip.gate().or(ctx, less, equal);

        result
    }


}