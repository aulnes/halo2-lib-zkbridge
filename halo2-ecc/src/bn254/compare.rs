#![allow(non_snake_case)]


use halo2_base::utils::BigPrimeField;
use halo2_base::gates::GateInstructions;
use crate::bigint::{big_is_equal, big_less_than,ProperCrtUint};
use crate::fields::FieldChip;

use super::FpChip;
use halo2_base::{ AssignedValue, Context};


// Compare a is less than or equal to b
// the constraint in the Mithril paper
pub struct CompareChip<'chip, F: BigPrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
}

impl<'chip, F: BigPrimeField> CompareChip<'chip, F> {

    pub fn new(fp_chip: &'chip FpChip<F>) -> Self {
        Self { fp_chip }
    }

    pub fn compare_result(
        &self,
        ctx: &mut Context<F>,
        a: ProperCrtUint<F>,
        b: ProperCrtUint<F>,
    ) -> AssignedValue<F>{
            
        let base_chip = self.fp_chip;

        let less = big_less_than::assign(
            base_chip.range(), 
            ctx, 
            a.clone(), 
            b.clone(), 
            base_chip.limb_bits,
            base_chip.limb_bases[1],
        );

        let equal = big_is_equal::assign(
            base_chip.gate(), 
            ctx, 
            a, 
            b,
        );

        let result = base_chip.gate().or(ctx, less, equal);

        result

    }



}