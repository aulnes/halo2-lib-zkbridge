use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
// use env_logger::init;
use halo2_base::gates::GateChip;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::Context;
use halo2_base::utils::BigPrimeField;
// use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use super::*;
use crate::bn254::{MerkleInfo, merkle_path_select::MerklePathSelectChip};
// use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use std::io::Read;
use rand::seq::SliceRandom; // For random selection

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    sk: String,
    stake: String,
    path: Vec<String>,
    index: Vec<bool>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleData {
    root: String,
    leaves: Vec<MerklePath>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct MerkleTreeCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    num_aggregation: u32,
    num_origin:u32,
}
fn f_from_string<F: BigPrimeField>(s: &str) -> F {
    let bytes:[u8; 32] = hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    F::from_bytes_le(&bytes)
}


fn merkle_path_select_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    _range: &RangeChip<F>,
    _params: MerkleTreeCircuitParams,
    root: F,
    merkle_paths: Vec<&MerklePath>,
    // actual_result: bool,
) {
    let mut poseidon_chip = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate_chip = GateChip::<F>::default();
    poseidon_chip.initialize_consts(ctx, &gate_chip);
    let merkle_path_select_chip = MerklePathSelectChip::new(&poseidon_chip, gate_chip);

    let merkle_infos: Vec<MerkleInfo<F>> = merkle_paths.iter().map(|path| {
        let sk = f_from_string::<Fr>(&path.sk);
        let stake = f_from_string::<F>(&path.stake);
        let pk = G1Affine::from(G1Affine::generator() * sk);
        let leaf = F::from_bytes_le(&pk.x.to_bytes());
        let path_vals: Vec<F> = path.path.iter().map(|s| f_from_string::<F>(s)).collect();
        let index = path.index.clone();
        MerkleInfo { leaf, stake, path: path_vals, index }
    }).collect();

    
    let result = merkle_path_select_chip.merkle_path_select_verify_batch(ctx, root, &merkle_infos);
    assert_eq!(*result.value(), F::from(1));
}


#[test]
fn test_merkle_path_select() {
    let run_path = "configs/bn254/merkle_tree_circuit.config";
    let path = run_path;
    let params: MerkleTreeCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    ).unwrap();

    let merkle_input_path = "data/merkle_tree_from_g1_{num}.json".replace("{num}", &params.num_origin.to_string());
    let mut file = File::open(merkle_input_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: MerkleData = serde_json::from_str(&data).expect("Invalid JSON");
    let root = f_from_string::<Fr>(&json_data.root);

    let mut rng = rand::thread_rng();
    let num_agg = params.num_aggregation as usize;
    let selected_leaves: Vec<&MerklePath> = json_data.leaves.choose_multiple(&mut rng, num_agg).collect();

    base_test().k(params.degree).run(|ctx, range| {
        merkle_path_select_test(ctx, range, params, root, selected_leaves);
    });

}


#[test]
fn bench_merkle_path_select() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_merkle_tree.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    
    let results_path = "results/bn254/merkle_tree_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,num_origin,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: MerkleTreeCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path = "data/merkle_tree_from_g1_{num}.json".replace("{num}", &bench_params.num_origin.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: MerkleData = serde_json::from_str(&data).expect("Invalid JSON");
        let root = f_from_string::<Fr>(&json_data.root);

        let mut rng = rand::thread_rng();
        let num_agg = bench_params.num_aggregation as usize;
        let selected_leaves: Vec<&MerklePath> = json_data.leaves.choose_multiple(&mut rng, num_agg).collect();

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (root, selected_leaves.clone()),
            (root, selected_leaves),
            |ctx, range, (root, selected_leaves)| {
                merkle_path_select_test(ctx.main(),range, bench_params,root, selected_leaves);
            },
        );

        writeln!(fs_results, 
            "{},{},{},{},{},{},{},{},{},{:?},{},{:?}",
            k,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.num_aggregation,
            bench_params.num_origin,
            stats.proof_time,
            stats.proof_size,
            stats.verify_time,
        )?;
    }
    Ok(())
}