use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::ff::{Field, PrimeField};
use halo2_base::utils::BigPrimeField;
use halo2_base::Context;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use super::*;
use crate::bn254::index_check::IndexCheckChip;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct IndexCheckCircuitParams {
    degree: u32,
    lookup_bits: usize,
    num: u32,
}

fn index_check_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: IndexCheckCircuitParams,
    indexes: Vec<F>,
) {
    let index_check_chip = IndexCheckChip::new(range);
    let max_index = F::from(params.num as u64);
    let result = index_check_chip.index_check(ctx, &indexes, max_index);
    range.gate().assert_is_const(ctx, &result, &F::ONE);
}
#[test]
#[ignore = "run explicitly through the component benchmark runner"]
fn bench_index_check() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::var("HALO2_BENCH_CONFIG")
        .unwrap_or_else(|_| "configs/bn254/bench_index_check.config".to_owned());
    let bench_params_file =
        File::open(&config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();

    let results_path = std::env::var("HALO2_BENCH_OUTPUT")
        .unwrap_or_else(|_| "results/bn254/index_check_bench.csv".to_owned());
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,native_limb_bits,native_num_limbs,num_aggregation,vk_time_s,pk_time_s,proof_time_s,proof_size_bytes,verify_time_s")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: IndexCheckCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let mut rng = StdRng::seed_from_u64(0);
        let mut indexes: Vec<Fr> = (1..=bench_params.num).map(|x| Fr::from(x as u64)).collect();
        indexes.shuffle(&mut rng);

        let mut keygen_indexes = indexes.clone();
        keygen_indexes.reverse();
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            keygen_indexes,
            indexes,
            |pool, range, indexes| {
                index_check_test(pool.main(), range, bench_params, indexes);
            },
        );
        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            bench_params.degree,
            stats.config_params.num_advice_per_phase.iter().sum::<usize>(),
            stats.config_params.num_lookup_advice_per_phase.iter().sum::<usize>(),
            stats.config_params.num_fixed,
            bench_params.lookup_bits,
            super::super::native_integer::LIMB_BITS,
            (Fr::NUM_BITS as usize + super::super::native_integer::LIMB_BITS - 1)
                / super::super::native_integer::LIMB_BITS,
            bench_params.num,
            stats.vk_time.as_secs_f64(),
            stats.pk_time.as_secs_f64(),
            stats.proof_time.as_secs_f64(),
            stats.proof_size,
            stats.verify_time.as_secs_f64(),
        )?;
    }
    Ok(())
}
#[test]
fn benchmark_regression_index_bounds_and_duplicates() {
    let high = Fr::from(2).pow_vartime([253]);
    let cases = [
        (vec![], Fr::ZERO, true),
        (vec![Fr::ZERO], Fr::ZERO, true),
        (vec![Fr::ZERO, Fr::ONE], Fr::ONE, true),
        (vec![Fr::ONE], Fr::ZERO, false),
        (vec![Fr::ONE, Fr::ONE], Fr::ONE, false),
        (vec![high], high, true),
        (vec![high], high - Fr::ONE, false),
        (vec![-Fr::from(2), -Fr::ONE], -Fr::ONE, true),
        (vec![-Fr::ONE], -Fr::from(2), false),
        (vec![-Fr::ONE], Fr::from(10), false),
    ];
    for (indexes, max, valid) in cases {
        base_test().k(10).lookup_bits(8).expect_satisfied(valid).run(|ctx, range| {
            let chip = IndexCheckChip::new(range);
            let result = chip.index_check(ctx, &indexes, max);
            range.gate().assert_is_const(ctx, &result, &Fr::ONE);
        });
    }
}

#[test]
fn benchmark_regression_index_input_binding() {
    for tamper_max in [false, true] {
        base_test().k(10).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
            let chip = IndexCheckChip::new(range);
            let index = ctx.load_witness(Fr::ONE);
            let max = ctx.load_witness(Fr::from(2));
            let result = chip.index_check_assigned(ctx, &[index], max);
            range.gate().assert_is_const(ctx, &result, &Fr::ONE);
            // A malicious witness cannot change the input without changing
            // the integer decomposition used by the comparison.
            if tamper_max {
                max.debug_prank(ctx, Fr::ZERO);
            } else {
                index.debug_prank(ctx, -Fr::ONE);
            }
        });
    }
}

#[test]
fn benchmark_regression_index_changed_witnesses_same_key() {
    base_test().k(10).lookup_bits(8).bench_builder(
        (vec![Fr::ZERO, Fr::ONE], Fr::from(2)),
        (vec![-Fr::from(2), -Fr::ONE], -Fr::ONE),
        |pool, range, (indexes, max)| {
            let result = IndexCheckChip::new(range).index_check(pool.main(), &indexes, max);
            range.gate().assert_is_const(pool.main(), &result, &Fr::ONE);
        },
    );
}
