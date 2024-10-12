use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
// use env_logger::init;
use halo2_base::{gates::GateChip, halo2_proofs::{arithmetic::CurveAffine, halo2curves::serde::SerdeObject}, poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher}, utils::ScalarField};
use halo2_base::Context;
use halo2_base::utils::BigPrimeField;
use itertools::Itertools;
// use rand_core::OsRng;
// use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use super::*;
use crate::bn254::{
    MerkleInfo, merkle_tree::MerkleTreeChip, 
    bls_signature::BlsSignatureChip, 
    msp::MspChip,
};
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use std::io::Read;
use rand::seq::SliceRandom; // For random selection
use poseidon::Poseidon;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct key_struct {
    sk: String,
    pk_x: String,
    pk_y: String,
}

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
pub struct MspData {
    degree: u32,
    message: String,
    hash_msg: String,
    sks: Vec<String>,
    rng_seed: String,
    signatures: Vec<g2_struct>,
    weighting_seed : String,
    e_is: Vec<String>,
    ivk: g1_struct,
    isig: g2_struct,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MspData2 {
    degree: u32,
    message: String,
    hash_msg: String,
    sks: Vec<String>,
    rng_seed: String,
    signatures: Vec<g1_struct>,
    weighting_seed : String,
    e_is: Vec<String>,
    ivk: g2_struct,
    isig: g1_struct,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CombineBlsMtCircuitParams {
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
fn fr_from_string(s: &str) -> Fr {
    let bytes:[u8; 32] = hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fr::from_bytes(&bytes).unwrap();
    result
}
fn fq_from_string(s: &str) -> Fq {
    let bytes:[u8; 32] = hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fq::from_bytes(&bytes).unwrap();
    result
}
fn fq2_from_string(c0: &str, c1: &str) -> Fq2 {
    let c0_bytes:[u8; 32] = hex::decode(c0).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let c1_bytes:[u8; 32] = hex::decode(c1).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fq2::new(Fq::from_bytes(&c0_bytes).unwrap(), Fq::from_bytes(&c1_bytes).unwrap());
    result
}

fn g1_from_string(s:g1_struct) -> G1Affine {
    G1Affine::from_xy(fq_from_string(&s.x), fq_from_string(&s.y)).unwrap()
}

fn g2_from_string(s:g2_struct) -> G2Affine {
    G2Affine::from_xy(fq2_from_string(&s.x_c0, &s.x_c1), fq2_from_string(&s.y_c0, &s.y_c1)).unwrap()
}

fn msp_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CombineBlsMtCircuitParams,
    g1: G1Affine,
    signatures: &[G2Affine],
    pubkeys: &[G1Affine],
    msghash: G2Affine,
    weighting_seed: F,
    ivk: G1Affine,
    isig: G2Affine,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let gate_chip = GateChip::<F>::default();
    let mut poseidon_chip = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    poseidon_chip.initialize_consts(ctx, &gate_chip);
    let msp_chip = MspChip::new(&bls_signature_chip, &poseidon_chip);
    let result = msp_chip.msp_verify(ctx, g1, signatures, pubkeys, msghash,weighting_seed,ivk,isig);

    assert_eq!(*result.value(), F::ONE);
}

fn msp_test2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CombineBlsMtCircuitParams,
    g2: G2Affine,
    signatures: &[G1Affine],
    pubkeys: &[G2Affine],
    msghash: G1Affine,
    weighting_seed: F,
    ivk: G2Affine,
    isig: G1Affine,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let gate_chip = GateChip::<F>::default();
    let mut poseidon_chip = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    poseidon_chip.initialize_consts(ctx, &gate_chip);
    let msp_chip = MspChip::new(&bls_signature_chip, &poseidon_chip);
    let result = msp_chip.msp_verify_2(ctx, g2, signatures, pubkeys, msghash,weighting_seed,ivk,isig);

    assert_eq!(*result.value(), F::ONE);
}
#[test]
fn test_msp() {
    let run_path = "configs/bn254/msp.config";
    let path = run_path;
    let params: CombineBlsMtCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    ).unwrap();

    let merkle_input_path = "data/data_for_msp_{num}.json".replace("{num}", &params.num_origin.to_string());
    let mut file = File::open(merkle_input_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: MspData = serde_json::from_str(&data).expect("Invalid JSON");
    let message = json_data.message.clone();
    let message = f_from_string::<Fr>(&message);
    let msg_hash = json_data.hash_msg.clone();
    let msg_hash_to_fr = fr_from_string(&msg_hash);
    let msg_hash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeaf);
    let sks = json_data.sks.iter().map(|x| fr_from_string(&x)).collect_vec();
    let selected_keys = sks.choose_multiple(&mut rng, params.num_aggregation as usize).collect_vec();
    let pubkeys = selected_keys.iter().map(|x| G1Affine::from(G1Affine::generator() * *x)).collect_vec();
    let signatures = json_data.signatures.iter().map(|x| g2_from_string(x.clone())).collect_vec();
    let weighting_seed = fr_from_string(&json_data.weighting_seed);
    let ivk = g1_from_string(json_data.ivk);
    let isig = g2_from_string(json_data.isig);

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        msp_test(ctx,range,params, G1Affine::generator(), &signatures, &pubkeys, msg_hash, weighting_seed, ivk, isig);
    });
}
#[test]
fn test2_msp(){
    let run_path = "configs/bn254/msp.config";
    let path = run_path;
    let params: CombineBlsMtCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    ).unwrap();

    let merkle_input_path = "data/data2_for_msp_{num}.json".replace("{num}", &params.num_origin.to_string());
    let mut file = File::open(merkle_input_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: MspData2= serde_json::from_str(&data).expect("Invalid JSON");
    let message = json_data.message.clone();
    let message = f_from_string::<Fr>(&message);
    let msg_hash = json_data.hash_msg.clone();
    let msg_hash_to_fr = fr_from_string(&msg_hash);
    let msg_hash = G1Affine::from(G1Affine::generator() * msg_hash_to_fr);

    let sks: Vec<Fr> = json_data.sks.iter().map(|x| fr_from_string(&x)).collect_vec();
    // vec<sk,pk>
    let sk_pks  = sks.iter().map(|x| {
        let pk = G2Affine::from(G2Affine::generator() * x);
        (x.clone(), pk)
    }).collect_vec();
    // rng is from "deadbeaf"
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeaf);
    let selected_keys = sk_pks.choose_multiple(&mut rng, params.num_aggregation as usize).collect_vec();
    let signatures: Vec<G1Affine> = json_data.signatures.iter().map(|x| g1_from_string(x.clone())).collect_vec();
    let weighting_seed = fr_from_string(&json_data.weighting_seed);
    // let e_is: Vec<Fr> = json_data.e_is.iter().map(|x| fr_from_string(x)).collect_vec();
    let ivk = g2_from_string(json_data.ivk);
    let isig = g1_from_string(json_data.isig);

    let pubkeys = selected_keys.iter().map(|x| x.1).collect_vec();

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        msp_test2(ctx,range,params, G2Affine::generator(), &signatures, &pubkeys, msg_hash, weighting_seed, ivk, isig);
    });

}
#[test]
fn bench_msp() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_msp.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/msp_bench.csv";
    let mut results_file = File::create(results_path).unwrap();
    writeln!(results_file, "num_advice,degree,lookup_bits,limb_bits,num_limbs,num_aggregation,num_origin,proving_time,proof_size,verification_time").unwrap();

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CombineBlsMtCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path = "data/data_for_msp_{num}.json".replace("{num}", &bench_params.num_origin.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: MspData = serde_json::from_str(&data).expect("Invalid JSON");
        let message = json_data.message.clone();
        let message = f_from_string::<Fr>(&message);
        let msg_hash = json_data.hash_msg.clone();
        let msg_hash_to_fr = fr_from_string(&msg_hash);
        let msg_hash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeaf);
        let sks = json_data.sks.iter().map(|x| fr_from_string(&x)).collect_vec();
        let selected_keys = sks.choose_multiple(&mut rng, bench_params.num_aggregation as usize).collect_vec();
        let pubkeys = selected_keys.iter().map(|x| G1Affine::from(G1Affine::generator() * *x)).collect_vec();
        let signatures = json_data.signatures.iter().map(|x| g2_from_string(x.clone())).collect_vec();
        let weighting_seed = fr_from_string(&json_data.weighting_seed);
        let ivk = g1_from_string(json_data.ivk);
        let isig = g2_from_string(json_data.isig);

        
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (G1Affine::generator(), signatures.clone(), pubkeys.clone(), msg_hash, weighting_seed, ivk, isig),
            (G1Affine::generator(), signatures, pubkeys, msg_hash, weighting_seed, ivk, isig),
            |pool, range, (g1, signatures, pubkeys, msg_hash, weighting_seed, ivk, isig)| {
                msp_test(
                    pool.main(),
                    range,
                    bench_params,
                    g1,
                    &signatures,
                    &pubkeys,
                    msg_hash,
                    weighting_seed,
                    ivk,
                    isig,
                );
            },
        );

        writeln!(
            results_file,
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.num_advice,
            bench_params.degree,
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

#[test]
fn bench2_msp() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_msp.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();

    let results_path = "results/bn254/msp_bench2.csv";
    let mut results_file = File::create(results_path).unwrap();
    writeln!(results_file, "num_advice,degree,lookup_bits,limb_bits,num_limbs,num_aggregation,num_origin,proving_time,proof_size,verification_time").unwrap();

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines(){
        let bench_params: CombineBlsMtCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path = "data/data2_for_msp_{num}.json".replace("{num}", &bench_params.num_origin.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: MspData2= serde_json::from_str(&data).expect("Invalid JSON");
        let message = json_data.message.clone();
        let message = f_from_string::<Fr>(&message);
        let msg_hash = json_data.hash_msg.clone();
        let msg_hash_to_fr = fr_from_string(&msg_hash);
        let msg_hash = G1Affine::from(G1Affine::generator() * msg_hash_to_fr);

        let sks: Vec<Fr> = json_data.sks.iter().map(|x| fr_from_string(x)).collect_vec();
        // vec<sk,pk>
        let sk_pks  = sks.iter().map(|x| {
            let pk = G2Affine::from(G2Affine::generator() * x);
            (x.clone(), pk)
        }).collect_vec();
        // rng is from "deadbeaf"
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeaf);
        let selected_keys = sk_pks.choose_multiple(&mut rng, bench_params.num_aggregation as usize).collect_vec();
        let signatures: Vec<G1Affine> = json_data.signatures.iter().map(|x| g1_from_string(x.clone())).collect_vec();
        let weighting_seed = fr_from_string(&json_data.weighting_seed);
        // let e_is: Vec<Fr> = json_data.e_is.iter().map(|x| fr_from_string(x)).collect_vec();
        let ivk = g2_from_string(json_data.ivk);
        let isig = g1_from_string(json_data.isig);

        let pubkeys = selected_keys.iter().map(|x| x.1).collect_vec();

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (G2Affine::generator(), signatures.clone(), pubkeys.clone(), msg_hash, weighting_seed, ivk, isig),
            (G2Affine::generator(), signatures, pubkeys, msg_hash, weighting_seed, ivk, isig),
            |pool, range, (g2, signatures, pubkeys, msg_hash, weighting_seed, ivk, isig)| {
                msp_test2(
                    pool.main(),
                    range,
                    bench_params,
                    g2,
                    &signatures,
                    &pubkeys,
                    msg_hash,
                    weighting_seed,
                    ivk,
                    isig,
                );
            },
        );

        writeln!(
            results_file,
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.num_advice,
            bench_params.degree,
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