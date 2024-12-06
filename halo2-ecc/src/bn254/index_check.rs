use halo2_base::{ gates::GateInstructions, utils::{fe_to_biguint, BigPrimeField}, AssignedValue, Context};
use crate::{bigint::{big_is_equal, big_less_than, FixedOverflowInteger}, fields::FieldChip};

use super::FpChip;



pub struct IndexCheckChip<'chip,F:BigPrimeField>{
    pub fp_chip: &'chip FpChip<'chip, F>,
}

impl<'chip,F:BigPrimeField> IndexCheckChip<'chip,F>{
    pub fn new(fp_chip: &'chip FpChip<'chip, F>,) -> Self {
        Self { fp_chip }
    }
    
    pub fn index_check(
        &self,
        ctx: &mut Context<F>,
        indexes: &[F],
        max_index: F,
    ) -> AssignedValue<F> {
        // println!("indexses: {:?}", indexes);
        let len = indexes.len();

        let base_chip = self.fp_chip;
        // println!("max_index: {:?}", max_index);
        let max = ctx.load_witness(max_index);
        // println!("max: {:?}", max);
        let max_index_bigint = fe_to_biguint(max.value());
        let m = FixedOverflowInteger::<F>::from_native(&max_index_bigint, base_chip.num_limbs, base_chip.limb_bits);
        let m = m.assign(ctx);

        let mut is_valids = Vec::<AssignedValue<F>>::new();
        
        let mut indexes_assigned = Vec::<AssignedValue<F>>::new();
        for i in 0..len{
            let index = indexes[i];
            let index = ctx.load_witness(index);
            indexes_assigned.push(index);
        }

        for i in 0..len {
            let index = indexes_assigned[i].clone();
            let index_bigint = fe_to_biguint(index.value());
            let index = FixedOverflowInteger::<F>::from_native(&index_bigint, base_chip.num_limbs, base_chip.limb_bits);
            let index = index.assign(ctx);

            let less = big_less_than::assign(
                base_chip.range(), 
                ctx, 
                index.clone(),
                m.clone(),
                base_chip.limb_bits,
                base_chip.limb_bases[1],
            );

            let equal = big_is_equal::assign(
                base_chip.gate(), 
                ctx, 
                index,
                m.clone(),
            );
            
            let result = base_chip.gate().or(ctx, less, equal);
            // println!("result: {:?}", result.value());
            is_valids.push(result);
        }

        for i in 0..len {
            for j in i+1..len{
                let eq = base_chip.gate().is_equal(ctx, indexes_assigned[i], indexes_assigned[j]);
                let is_valid = base_chip.gate().is_zero(ctx, eq);
                is_valids.push(is_valid);
            }
        }

        let mut result = is_valids[0].clone();
        for i in 1..is_valids.len(){
            result = base_chip.gate().and(ctx, result, is_valids[i].clone());
        }
        result
    }
    
}