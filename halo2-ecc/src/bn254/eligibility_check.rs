#![allow(non_snake_case)]


use halo2_base::utils::{fe_to_biguint, BigPrimeField};
use crate::bigint::{big_is_equal, big_less_than, FixedOverflowInteger};
use crate::fields::FieldChip;
use halo2_base::gates::{GateChip, GateInstructions};
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
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
        let scalar_chip =
        FpChip::<F>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

        let ev_bigint = fe_to_biguint(ev_assigned.value());
        let ev = FixedOverflowInteger::<F>::from_native(&ev_bigint, scalar_chip.num_limbs, scalar_chip.limb_bits);
        let ev = ev.assign(ctx);

        let phi_stake_bigint = fe_to_biguint(phi_stake_assigned.value());
        let phi_stake = FixedOverflowInteger::<F>::from_native(&phi_stake_bigint, scalar_chip.num_limbs, scalar_chip.limb_bits);
        let phi_stake = phi_stake.assign(ctx);


        // println!("ev: {:?}", ev_assigned.value());
        // println!("ph: {:?}", phi_stake_assigned.value());

        

        //let ev_pint = ProperUint(vec![ev_assigned]);
        //let phi_stake_pint = ProperUint(vec![phi_stake_assigned]);

        let less = big_less_than::assign(
            base_chip.range(), 
            ctx, 
            ev.clone(),
            phi_stake.clone(),
            base_chip.limb_bits,
            base_chip.limb_bases[1],
        );

        // println!("less:{:?}", less.value());

        let equal = big_is_equal::assign(
            base_chip.gate(), 
            ctx, 
            ev,
            phi_stake,
        );

        // println!("equal:{:?}", equal.value());

        let result = base_chip.gate().or(ctx, less, equal);

        result
    }


    pub fn eligibility_check_batch(
        &self,
        ctx: &mut Context<F>,
        phi_stakes: &[F],
        signatures: &[G2Affine],
        msghash: G2Affine,
        indexes : &[F],
    ) -> AssignedValue<F>{

        let len = phi_stakes.len();
        let mut results = Vec::new();

        for i in 0..len{

            let res = self.eligibility_check_one(
                ctx,
                phi_stakes[i],
                signatures[i],
                msghash,
                indexes[i]);
            
            results.push(res);

            // println!("res:{:?}", res.value());
        }

        let base_chip = self.fp_chip;

        let mut all_one = ctx.load_witness(F::from(1));

        for res in results{

            all_one = base_chip.gate().and(ctx, all_one, res);


        }


        all_one

    }



}