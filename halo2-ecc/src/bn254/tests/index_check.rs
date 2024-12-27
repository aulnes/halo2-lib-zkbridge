use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
// use env_logger::init;
use halo2_base::Context;
use halo2_base::utils::BigPrimeField;

// use rand_core::OsRng;
// use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use super::*;
use crate::bn254::index_check::IndexCheckChip;
use rand::seq::SliceRandom;  // 引入 SliceRandom 特征
use rand::thread_rng;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct IndexCheckCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    num: u32,
}

fn index_check_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: IndexCheckCircuitParams,
    indexes: Vec<F>,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let index_check_chip = IndexCheckChip::new(&fp_chip);
    let max_index = F::from(params.num as u64);
    // println!("max_index: {:?}", max_index);
    let result = index_check_chip.index_check(ctx, &indexes, max_index);
    assert_eq!(*result.value(), F::ONE);
}
#[test]
fn bench_index_check()-> Result<(), Box<dyn std::error::Error>>{
    let config_path = "configs/bn254/bench_index_check.config";
    let bench_params_file = File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();

    let results_path = "results/bn254/index_check_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: IndexCheckCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        // 生成 num 长度的 1 到 num 的乱序数组
        let mut rng = thread_rng();
        let mut indexes: Vec<Fr> = (1..=bench_params.num).map(|x| Fr::from(x as u64)).collect();
        indexes.shuffle(&mut rng);

        // println!("indexes: {:?}", indexes);
        // println!("indexes.len(): {:?}", indexes.len());

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            indexes.clone(),
            indexes,
            |pool, range, indexes| {
                index_check_test(
                    pool.main(),
                    range,
                    bench_params,
                    indexes,
                );
            },
        );
        writeln!(
            fs_results, 
            "{},{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.num,
            stats.proof_time,
            stats.proof_size,
            stats.verify_time,
        )?;
    }
    Ok(())
}