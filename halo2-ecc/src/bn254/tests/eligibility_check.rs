#![allow(non_snake_case)]
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
// use env_logger::init;
use halo2_base::{gates::GateChip, halo2_proofs::arithmetic::CurveAffine, poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher}};
use halo2_base::Context;
use halo2_base::utils::BigPrimeField;
use itertools::Itertools;
// use rand_core::OsRng;
// use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use super::*;
use crate::bn254::eligibility_check::EligibilityCheckChip;
use crate::halo2_proofs::halo2curves::bn256::{Fq,G2Affine};
use std::io::Read;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct g1_struct {
    x: String,
    y: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct g2_struct {
    x_c0: String,
    x_c1: String,
    y_c0: String,
    y_c1: String,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EligibilityInfo<F> {
    phi_stake: F,
    signature: G2Affine,
    msghash: G2Affine,
    index: F,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EligibilityData {
    phi_stakes: Vec<String>,
    signatures: Vec<g2_struct>,
    msghash: String,
    indexes: Vec<String>,
}



#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct EligibilityCheckCircuitParams {
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
fn fr_from_string(s: &str) -> Fr {
    let bytes:[u8; 32] = hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fr::from_bytes(&bytes).unwrap();
    result
}
// fn fq_from_string(s: &str) -> Fq {
//     let bytes:[u8; 32] = hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
//     let result = Fq::from_bytes(&bytes).unwrap();
//     result
// }
fn fq2_from_string(c0: &str, c1: &str) -> Fq2 {
    let c0_bytes:[u8; 32] = hex::decode(c0).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let c1_bytes:[u8; 32] = hex::decode(c1).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fq2::new(Fq::from_bytes(&c0_bytes).unwrap(), Fq::from_bytes(&c1_bytes).unwrap());
    result
}

// fn g1_from_string(s:g1_struct) -> G1Affine {
//     G1Affine::from_xy(fq_from_string(&s.x), fq_from_string(&s.y)).unwrap()
// }

fn g2_from_string(s:g2_struct) -> G2Affine {
    G2Affine::from_xy(fq2_from_string(&s.x_c0, &s.x_c1), fq2_from_string(&s.y_c0, &s.y_c1)).unwrap()
}


fn eligibility_check_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: EligibilityCheckCircuitParams,
    phi_stakes: &[F],
    signatures: &[G2Affine],
    msghash: G2Affine,
    indexes : &[F],
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let mut poseidon_chip = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate_chip = GateChip::<F>::default();
    poseidon_chip.initialize_consts(ctx, &gate_chip);

    let eligibility_check_chip = EligibilityCheckChip::new(&poseidon_chip, gate_chip, &fp_chip);


    let result = eligibility_check_chip.eligibility_check_batch(
        ctx, 
        phi_stakes, 
        signatures, 
        msghash, 
        indexes);

    assert_eq!(*result.value(), F::ONE);

}

#[test]
fn test_eligibility_check(){
    let run_path = "configs/bn254/eligibility_check.config";
    let path = run_path;
    let params: EligibilityCheckCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    ).unwrap();


    let eligibility_info_path = "data/data_for_eligibility_{num}.json".replace("{num}", &params.num.to_string());
    let mut file = File::open(eligibility_info_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: EligibilityData = serde_json::from_str(&data).expect("Invalid JSON");

    let msg_hash = json_data.msghash.clone();
    let msg_hash_to_fr = fr_from_string(&msg_hash);
    let msghash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);
    let signatures = json_data.signatures.iter().map(|x| g2_from_string(x.clone())).collect_vec();
    let indexes =  json_data.indexes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();
    let phi_stakes = json_data.phi_stakes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        eligibility_check_test(ctx,range,params, &phi_stakes, &signatures, msghash, &indexes);
    });

}

#[test]
fn bench_eligibility_check() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_eligibility_check.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    
    let results_path = "results/bn254/eligibility_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,limb_bits,num_limbs,num,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: EligibilityCheckCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path = "data/data_for_eligibility_{num}.json".replace("{num}", &bench_params.num.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: EligibilityData = serde_json::from_str(&data).expect("Invalid JSON");
        let msg_hash = json_data.msghash.clone();
        let msg_hash_to_fr = fr_from_string(&msg_hash);
        let msghash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);
        let signatures = json_data.signatures.iter().map(|x| g2_from_string(x.clone())).collect_vec();
        let indexes =  json_data.indexes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();
        let phi_stakes = json_data.phi_stakes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();        

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (msghash.clone(), signatures.clone(), indexes.clone(),phi_stakes.clone()),
            (msghash, signatures, indexes,phi_stakes),
            |ctx, range, (msghash, signatures, indexes,phi_stakes)| {
                eligibility_check_test(ctx.main(),range, bench_params,&phi_stakes, &signatures, msghash, &indexes);
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