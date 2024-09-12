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
pub struct MspData {
    degree: u32,
    message: String,
    hash_msg: String,
    pubkeys: Vec<key_struct>,
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

    let mut rng = rand::thread_rng();
    let num_agg = params.num_aggregation as usize;
    let selected_keys = json_data.pubkeys.choose_multiple(&mut rng, num_agg).collect_vec();
    let sks: Vec<Fr> = selected_keys.iter().map(|x| fr_from_string(&x.sk)).collect_vec();
    let pubkeys: Vec<G1Affine> = selected_keys.iter().map(|x| G1Affine::from_xy(fq_from_string(&x.pk_x), fq_from_string(&x.pk_y)).unwrap()).collect_vec();

    let signatures = sks.iter().map(|x| G2Affine::from(msg_hash * x)).collect_vec();

    // weighting_seed = H(signatures[0].x,signatures[1].x,...)
    let mut hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
    let mut sigs_x: Vec<Fr> = Vec::new();
    for sig in signatures.iter() {
        let sig_x_c0_bytes = sig.x.c0.to_bytes();
        let six_x_c0_fr = Fr::from_bytes(&sig_x_c0_bytes).unwrap();
        sigs_x.push(six_x_c0_fr);
    }
    hasher.update(&sigs_x[..]);
    let weighting_seed = hasher.squeeze();

    // e_i = H(i,weighting_seed) for i in 0..n where n is the number of public keys
    let e_is  = pubkeys.iter().enumerate().map(|(i, _)| {
        let mut hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
        hasher.update(&[Fr::from(i as u64), weighting_seed]);
        hasher.squeeze()
    }).collect::<Vec<_>>();

    

    // ivk = \sigma pk_i*e_i
    let products = pubkeys.iter().zip(e_is.iter()).map(|(pk, e_i)| {
        G1Affine::from(pk * (*e_i))
    }).collect::<Vec<_>>();

    let mut ivk = products[0];
    for product in products.iter().skip(1) {
        ivk = (ivk + product).into();
    }

    // isig = \sigma sig_i*e_i
    let products = signatures.iter().zip(e_is.iter()).map(|(sig, e_i)| {
        G2Affine::from(sig * (*e_i))
    }).collect::<Vec<_>>();

    let mut isig = products[0];
    for product in products.iter().skip(1) {
        isig = (isig + product).into();
    }

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        msp_test(ctx,range,params, G1Affine::generator(), &signatures, &pubkeys, msg_hash, weighting_seed, ivk, isig);
    });
}

