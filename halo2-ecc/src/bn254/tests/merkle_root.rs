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
use crate::bn254::merkle_root::MerkleRootChip;
// use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use std::io::Read;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleRootData {
    root: String,
    sks: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct MerkleRootCircuitParams {
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

fn f_from_string<F: BigPrimeField>(s: &str) -> F {
    let bytes:[u8; 32] = hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    F::from_bytes_le(&bytes)
}


fn merkle_root_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    _range: &RangeChip<F>,
    _params: MerkleRootCircuitParams,
    root: F,
    leaves: Vec<String>,
) {
    let mut poseidon_chip = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate_chip = GateChip::<F>::default();
    poseidon_chip.initialize_consts(ctx, &gate_chip);
    let merkle_root_chip = MerkleRootChip::new(&poseidon_chip, gate_chip);


    let sks : Vec<Fr> = leaves.iter().map(|s| f_from_string::<Fr>(s)).collect();
    let pks : Vec<G1Affine> = sks.iter().map(|sk| G1Affine::from(G1Affine::generator() * sk)).collect();
    let pkxs : Vec<F> = pks.iter().map(|pk| F::from_bytes_le(&pk.x.to_bytes())).collect();

    let result = merkle_root_chip.merkle_root_verify(ctx, root, pkxs);
    assert_eq!(*result.value(), F::from(1));

}

#[test]
fn test_merkle_root(){
    let run_path = "configs/bn254/merkle_root_circuit.config";
    let path = run_path;
    let params: MerkleRootCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    ).unwrap();


    let merkle_root_path = "data/whole_merkle_{num}.json".replace("{num}", &params.num.to_string());
    let mut file = File::open(merkle_root_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data : MerkleRootData = serde_json::from_str(&data).expect("Invalid JSON");

    let root = f_from_string::<Fr>(&json_data.root);
    let leaves = json_data.sks;

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        merkle_root_test(ctx,range,params, root, leaves);
    });
}

#[test]
fn bench_merkle_root() -> Result<(), Box<dyn std::error::Error>>{

    let config_path = "configs/bn254/bench_merkle_root.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();   

    let results_path = "results/bn254/merkle_root_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,limb_bits,num_limbs,num,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: MerkleRootCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);   

        let merkle_root_path = "data/whole_merkle_{num}.json".replace("{num}", &bench_params.num.to_string());
        let mut file = File::open(merkle_root_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data : MerkleRootData = serde_json::from_str(&data).expect("Invalid JSON");
        let root = f_from_string::<Fr>(&json_data.root);
        let leaves = json_data.sks;

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (root, leaves.clone()),
            (root, leaves),
            |ctx, range, (root, leaves)| {
                merkle_root_test(ctx.main(),range, bench_params,root, leaves);
            },
        );
        
        writeln!(fs_results, 
            "{},{},{},{},{},{},{},{},{:?},{},{:?}",
            k,
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