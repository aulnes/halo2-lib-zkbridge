// use halo2_base::{gates::{GateChip, GateInstructions}, poseidon::PoseidonChip, utils::BigPrimeField, AssignedValue, Context};




// pub struct ShuffleChip<'chip, F: BigPrimeField> {
//     pub poseidon_chip: PoseidonChip<'chip, F, 3, 2>,
//     pub gate_chip: GateChip<F>,
// }

// impl<'chip, F: BigPrimeField> ShuffleChip<'chip, F>{
//     pub fn new(poseidon_chip: PoseidonChip<'chip, F, 3, 2>, gate_chip: GateChip<F>) -> Self {
//         Self { poseidon_chip, gate_chip }
//     }

//     pub fn shuffle_verify(
//         &self,
//         ctx: &mut Context<F>,
//         original: Vec<F>,
//         shuffled: Vec<F>,
//         permutation: Vec<usize>,
//     ) -> AssignedValue<F> {
//         assert_eq!(original.len(), shuffled.len());
//         assert_eq!(original.len(), permutation.len());

//         let original = original
//             .into_iter()
//             .map(|x| ctx.load_witness(x))
//             .collect::<Vec<_>>();
//         let shuffled = shuffled
//             .into_iter()
//             .map(|x| ctx.load_witness(x))
//             .collect::<Vec<_>>();
//         let permutation = permutation
//             .into_iter()
//             .map(|x| ctx.load_witness(F::from(x as u64)))
//             .collect::<Vec<_>>();

//         let mut shuffled = shuffled;
//         for i in 0..original.len() {
//             let index = permutation[i];
//             let original_i = original[i];
//             let shuffled_i = shuffled.pop().unwrap();
//             shuffled.push(shuffled_i);
//         }

//         let shuffled_i = shuffled.pop().unwrap();
//         let zero = ctx.load_witness(F::ZERO);
//         let result = self.gate_chip.is_equal(ctx, shuffled_i, zero);
//         result
//     }
// }