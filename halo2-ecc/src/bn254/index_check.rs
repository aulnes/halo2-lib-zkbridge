use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::BigPrimeField,
    AssignedValue, Context,
};

use super::native_integer::{canonical_uint, less_than_or_equal};

pub struct IndexCheckChip<'chip, F: BigPrimeField> {
    pub range: &'chip RangeChip<F>,
}

impl<'chip, F: BigPrimeField> IndexCheckChip<'chip, F> {
    /// Uses the native-field range chip directly; no non-native Fq chip is needed.
    pub fn new(range: &'chip RangeChip<F>) -> Self {
        Self { range }
    }

    /// Returns whether all indexes are distinct and in [0, max_index], with
    /// canonical native-field integer ordering. Empty lists are valid.
    /// The inclusive upper bound and acceptance of zero preserve the original
    /// predicate; callers requiring one-based indices must enforce that too.
    pub fn index_check_assigned(
        &self,
        ctx: &mut Context<F>,
        indexes: &[AssignedValue<F>],
        max_index: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let range = self.range;
        let gate = range.gate();
        let max = canonical_uint(ctx, range, max_index);
        let mut result = ctx.load_constant(F::ONE);
        for &index in indexes {
            let index = canonical_uint(ctx, range, index);
            let in_range = less_than_or_equal(ctx, range, &index, &max);
            result = gate.and(ctx, result, in_range);
        }
        for (i, &index) in indexes.iter().enumerate() {
            for &other in &indexes[i + 1..] {
                let equal = gate.is_equal(ctx, index, other);
                let distinct = gate.not(ctx, equal);
                result = gate.and(ctx, result, distinct);
            }
        }
        result
    }

    pub fn index_check(
        &self,
        ctx: &mut Context<F>,
        indexes: &[F],
        max_index: F,
    ) -> AssignedValue<F> {
        let indexes = indexes.iter().map(|&index| ctx.load_witness(index)).collect::<Vec<_>>();
        let max = ctx.load_witness(max_index);
        self.index_check_assigned(ctx, &indexes, max)
    }

    /// Returns whether the canonical integer indexes are strictly increasing
    /// and each is in [0, num_lotteries). The exclusive bound is fixed by the
    /// circuit, not supplied as a private witness. Empty lists are valid here;
    /// the enclosing certificate fixes a positive required number of tickets.
    pub fn strict_sorted_bounded_assigned(
        &self,
        ctx: &mut Context<F>,
        indexes: &[AssignedValue<F>],
        num_lotteries: u64,
    ) -> AssignedValue<F> {
        assert!(F::CAPACITY >= 64, "lottery bound requires a 64-bit native field");
        let range = self.range;
        let gate = range.gate();
        let bound = ctx.load_constant(F::from(num_lotteries));
        let bound = canonical_uint(ctx, range, bound);
        let indexes =
            indexes.iter().map(|&index| canonical_uint(ctx, range, index)).collect::<Vec<_>>();
        let mut result = ctx.load_constant(F::ONE);
        for index in &indexes {
            let at_or_above_bound = less_than_or_equal(ctx, range, &bound, index);
            let below_bound = gate.not(ctx, at_or_above_bound);
            result = gate.and(ctx, result, below_bound);
        }
        for adjacent in indexes.windows(2) {
            let nonincreasing = less_than_or_equal(ctx, range, &adjacent[1], &adjacent[0]);
            let increasing = gate.not(ctx, nonincreasing);
            result = gate.and(ctx, result, increasing);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::{
        halo2_proofs::halo2curves::{bn256::Fr, ff::Field},
        utils::testing::base_test,
    };

    #[test]
    fn certificate_regression_sorted_indexes_have_exclusive_fixed_bound() {
        let cases = [
            (vec![Fr::ZERO, Fr::from(3), Fr::from(9)], 10, true),
            (vec![Fr::ZERO], 10, true),
            (vec![Fr::from(9)], 10, true),
            (vec![Fr::from(10)], 10, false),
            (vec![Fr::from(2), Fr::from(2)], 10, false),
            (vec![Fr::from(3), Fr::from(2)], 10, false),
            (vec![-Fr::ONE], 10, false),
            (vec![Fr::ZERO], 0, false),
            (vec![], 0, true),
            (vec![], 10, true),
            (vec![Fr::from(u64::MAX - 1)], u64::MAX, true),
            (vec![Fr::from(u64::MAX)], u64::MAX, false),
        ];
        for (indexes, bound, expected) in cases {
            base_test().k(11).lookup_bits(8).expect_satisfied(expected).run(|ctx, range| {
                let indexes =
                    indexes.iter().map(|&value| ctx.load_witness(value)).collect::<Vec<_>>();
                let accepted =
                    IndexCheckChip::new(range).strict_sorted_bounded_assigned(ctx, &indexes, bound);
                range.gate().assert_is_const(ctx, &accepted, &Fr::ONE);
            });
        }
    }

    #[test]
    fn certificate_regression_sorted_indexes_reuse_caller_cells() {
        base_test().k(10).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
            let indexes = [Fr::ZERO, Fr::ONE].map(|value| ctx.load_witness(value));
            let accepted =
                IndexCheckChip::new(range).strict_sorted_bounded_assigned(ctx, &indexes, 2);
            range.gate().assert_is_const(ctx, &accepted, &Fr::ONE);
            indexes[1].debug_prank(ctx, Fr::ZERO);
        });
    }

    #[test]
    #[ignore = "real KZG proof: verifies that the lottery policy is fixed in the verification key"]
    fn certificate_index_parameter_real_proof() {
        use halo2_base::{
            gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
            halo2_proofs::plonk::{keygen_pk, keygen_vk},
            utils::{
                fs::gen_srs,
                testing::{check_proof, gen_proof},
            },
        };

        fn assign(builder: &mut RangeCircuitBuilder<Fr>, num_lotteries: u64, index: u64) {
            let range = RangeChip::new(8, builder.lookup_manager().clone());
            let ctx = builder.main(0);
            let index = ctx.load_witness(Fr::from(index));
            let accepted = IndexCheckChip::new(&range).strict_sorted_bounded_assigned(
                ctx,
                &[index],
                num_lotteries,
            );
            range.gate().assert_is_const(ctx, &accepted, &Fr::ONE);
        }

        let mut keygen = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
            .use_k(10)
            .use_lookup_bits(8);
        assign(&mut keygen, 10, 9);
        let config = keygen.calculate_params(Some(9));
        let params = gen_srs(10);
        let vk = keygen_vk(&params, &keygen).unwrap();
        let pk = keygen_pk(&params, vk, &keygen).unwrap();
        let break_points = keygen.break_points();
        drop(keygen);

        // Both witnesses satisfy the policy they were built against. Only the
        // first policy is authorized by this verification key. Reuse the exact
        // configured columns and breakpoints for the attempted policy change.
        for (num_lotteries, index, accepted) in [(10, 9, true), (11, 10, false)] {
            let mut prover = RangeCircuitBuilder::prover(config.clone(), break_points.clone());
            assign(&mut prover, num_lotteries, index);
            let proof = gen_proof(&params, &pk, prover);
            check_proof(&params, pk.get_vk(), &proof, accepted);
        }
    }
}
