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
use crate::bn254::{
    MerkleInfo, merkle_tree::MerkleTreeChip, 
    bls_signature::BlsSignatureChip, 
    combine_bls_mt::CombineBlsMtChip
};
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use std::io::Read;
use rand::seq::SliceRandom; // For random selection


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    sk: String,
    pk_x: String,
    pk_y: String,
    path: Vec<String>,
    index: Vec<bool>,
}



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleData {
    message: String,
    hash_msg: String,
    root: String,
    leaves: Vec<MerklePath>,
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

fn combine_bls_mt_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CombineBlsMtCircuitParams,
    root: F,
    merkle_infos: &[MerkleInfo<F>],
    g1: G1Affine,
    signatures: &[G2Affine],
    pubkeys: &[G1Affine],
    message: F,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let gate_chip = GateChip::<F>::default();
    let mut poseidon_chip = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    poseidon_chip.initialize_consts(ctx, &gate_chip);
    let merkle_tree_chip = MerkleTreeChip::new(&poseidon_chip, gate_chip);
    let combine_bls_mt_chip = CombineBlsMtChip::new(&bls_signature_chip, merkle_tree_chip);

    let result = combine_bls_mt_chip.combine_bls_mt_verify(ctx, root, merkle_infos, g1, signatures, pubkeys, message);

    assert_eq!(*result.value(), F::from(1));
}
#[test]
fn test_combine_bls_mt() {
    let run_path = "configs/bn254/combine_bls_mt.config";
    let path = run_path;
    let params: CombineBlsMtCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    ).unwrap();

    let merkle_input_path = "data/merkle_tree_from_g1_{num}.json".replace("{num}", &params.num_origin.to_string());
    let mut file = File::open(merkle_input_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: MerkleData = serde_json::from_str(&data).expect("Invalid JSON");
    let root = f_from_string::<Fr>(&json_data.root);
    let message = json_data.message.clone();
    let message = f_from_string(&message);
    let msg_hash = json_data.hash_msg.clone();
    let msg_hash_to_fr = fr_from_string(&msg_hash);
    let msg_hash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);

    let mut rng = rand::thread_rng();
    let num_agg = params.num_aggregation as usize;
    let selected_leaves: Vec<&MerklePath> = json_data.leaves.choose_multiple(&mut rng, num_agg).collect();
    let pubkeys = selected_leaves.iter().map(|x| 
        G1Affine::from_xy(fq_from_string(&x.pk_x), fq_from_string(&x.pk_y)).unwrap()
    ).collect_vec();
    let sks = selected_leaves.iter().map(|x| fr_from_string(&x.sk)).collect_vec();

    // TODO: fix this
    // let message_str = "msg_hash".to_string();
    // let msg_hash ="ec335129ec86d9704a3c93b47c7280fbe5d42b6768dd43ef613edb188f102b2e".to_string();
    // let msg_to_fr = fr_from_string(&msg_hash);
    // println!("msg_byte:{:?}",msg_to_fr);

    // let msg_hash = G2Affine::from(G2Affine::generator() * Fr::from(OsRng));
    // let msg_hash = G2Affine::from(G2Affine::generator() * Fr::from(123456));
    // let msg_hash = G2Affine::from(G2Affine::generator() * msg_to_fr);

    // println!("msg_hash:{:?}",msg_hash);

    let signatures = sks.iter().map(|x| G2Affine::from(msg_hash * x)).collect_vec();

    let merkle_infos = selected_leaves.iter().map(|path| {
        let leaf = fr_from_string(&path.pk_x);
        let path_vals: Vec<Fr> = path.path.iter().map(|s| f_from_string(s)).collect();
        let index = path.index.clone();
        MerkleInfo { leaf, path: path_vals, index }
    }).collect_vec();


    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        combine_bls_mt_test(ctx,range,params,root, &merkle_infos, G1Affine::generator()
                , &signatures, &pubkeys, message);
    });
}

#[test]
fn bench_merkle_tree() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_combine_bls_mt.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    
    let results_path = "results/bn254/combine_bls_mt_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,num_origin,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CombineBlsMtCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path = "data/merkle_tree_from_g1_{num}.json".replace("{num}", &bench_params.num_origin.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: MerkleData = serde_json::from_str(&data).expect("Invalid JSON");

        let root = f_from_string::<Fr>(&json_data.root);
        let message = json_data.message.clone();
        let message = f_from_string::<Fr>(&message);
        let msg_hash = json_data.hash_msg.clone();
        let msg_hash_to_fr = fr_from_string(&msg_hash);
        let msg_hash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);

        let mut rng = rand::thread_rng();
        let num_agg = bench_params.num_aggregation as usize;
        let selected_leaves: Vec<&MerklePath> = json_data.leaves.choose_multiple(&mut rng, num_agg).collect();
        let pubkeys = selected_leaves.iter().map(|x| 
            G1Affine::from_xy(fq_from_string(&x.pk_x), fq_from_string(&x.pk_y)).unwrap()
        ).collect_vec();
        let sks = selected_leaves.iter().map(|x| fr_from_string(&x.sk)).collect_vec();

        let signatures = sks.iter().map(|x| G2Affine::from(msg_hash * x)).collect_vec();
        let merkle_infos = selected_leaves.iter().map(|path| {
            let leaf = fr_from_string(&path.pk_x);
            let path_vals: Vec<Fr> = path.path.iter().map(|s| f_from_string(s)).collect();
            let index = path.index.clone();
            MerkleInfo { leaf, path: path_vals, index }
        }).collect_vec();
        let g1 = G1Affine::generator();
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (root, merkle_infos.clone(), g1, signatures.clone(), pubkeys.clone(), message.clone()),
            (root, merkle_infos, g1, signatures, pubkeys,  message),
            |ctx, range, (root, merkle_infos, g1, signatures, pubkeys, message)| {
                combine_bls_mt_test(
                    ctx.main(),
                    range,
                    bench_params,
                    root,
                    &merkle_infos,
                    g1,
                    &signatures,
                    &pubkeys,
                    message,
                );
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