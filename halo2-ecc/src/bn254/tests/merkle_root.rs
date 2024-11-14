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
use crate::bn254::{MerkleInfo, merkle_tree::MerkleTreeChip};
// use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use std::io::Read;
use rand::seq::SliceRandom; // For random selection



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
