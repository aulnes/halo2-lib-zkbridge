use super::*;
use crate::bn254::{merkle_tree::MerkleTreeChip, MerkleInfo};
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::halo2curves::ff::Field;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::utils::BigPrimeField;
use halo2_base::Context;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

fn native_hash(values: &[Fr]) -> Fr {
    let mut hasher = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);
    hasher.update(values);
    hasher.squeeze()
}

fn small_tree() -> (Fr, MerkleInfo<Fr>, MerkleInfo<Fr>) {
    let left = native_hash(&[Fr::from(3), Fr::from(5)]);
    let right = native_hash(&[Fr::from(7), Fr::from(11)]);
    (
        native_hash(&[left, right]),
        MerkleInfo { leaf: Fr::from(3), stake: Fr::from(5), path: vec![right], index: vec![true] },
        MerkleInfo { leaf: Fr::from(7), stake: Fr::from(11), path: vec![left], index: vec![false] },
    )
}

fn constrain_openings(ctx: &mut Context<Fr>, root: Fr, infos: &[MerkleInfo<Fr>]) {
    let gate = GateChip::default();
    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, &gate);
    let chip = MerkleTreeChip::new(&hasher, gate);
    let accepted = chip.merkle_tree_verify_batch(ctx, root, infos);
    chip.gate_chip.assert_is_const(ctx, &accepted, &Fr::ONE);
}

#[test]
fn benchmark_regression_merkle_valid_and_tampered_openings() {
    let (root, left, right) = small_tree();
    base_test().k(12).lookup_bits(10).run(|ctx, _| {
        constrain_openings(ctx, root, &[left.clone(), right]);
    });
    for tamper in 0..6 {
        let mut info = left.clone();
        let mut claimed_root = root;
        match tamper {
            0 => claimed_root += Fr::ONE,
            1 => info.leaf += Fr::ONE,
            2 => info.stake += Fr::ONE,
            3 => info.path[0] += Fr::ONE,
            4 => info.index[0] = false,
            _ => (),
        }
        let infos = if tamper == 5 { vec![] } else { vec![info] };
        base_test().k(12).lookup_bits(10).expect_satisfied(false).run(|ctx, _| {
            constrain_openings(ctx, claimed_root, &infos);
        });
    }
}

#[test]
fn benchmark_regression_merkle_direction_is_boolean() {
    // Even without constraining the computed root, a direction of two must fail.
    base_test().k(12).lookup_bits(10).expect_satisfied(false).run(|ctx, _| {
        let gate = GateChip::default();
        let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
        hasher.initialize_consts(ctx, &gate);
        let chip = MerkleTreeChip::new(&hasher, gate);
        let leaf = ctx.load_witness(Fr::from(3));
        let stake = ctx.load_witness(Fr::from(5));
        let sibling = ctx.load_witness(Fr::from(7));
        let direction = ctx.load_witness(Fr::from(2));
        chip.root_from_assigned(ctx, leaf, stake, &[sibling], &[direction]);
    });
}

#[test]
fn benchmark_regression_merkle_assigned_input_binding() {
    for input in 0..5 {
        base_test().k(12).lookup_bits(10).expect_satisfied(false).run(|ctx, _| {
            let (root, left, _) = small_tree();
            let gate = GateChip::default();
            let mut hasher =
                PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
            hasher.initialize_consts(ctx, &gate);
            let chip = MerkleTreeChip::new(&hasher, gate);
            let cells = [root, left.leaf, left.stake, left.path[0], Fr::ONE]
                .map(|value| ctx.load_witness(value));
            let accepted = chip.merkle_tree_verify_assigned(
                ctx,
                cells[0],
                cells[1],
                cells[2],
                &cells[3..4],
                &cells[4..5],
            );
            chip.gate_chip.assert_is_const(ctx, &accepted, &Fr::ONE);
            // Change the original caller's cell after constructing the internal witness.
            let changed = *cells[input].value() + Fr::ONE;
            cells[input].debug_prank(ctx, changed);
        });
    }
}

#[test]
fn benchmark_regression_merkle_changed_directions_same_key() {
    let (root, left, right) = small_tree();
    base_test().k(12).lookup_bits(10).bench_builder(left, right, |pool, _, info| {
        constrain_openings(pool.main(), root, &[info]);
    });
}

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

// Column counts are selected by the builder. Legacy shared configs may also
// contain strategy/column/limb keys; serde ignores them for compatibility with
// the separate merkle_path_select benchmarks. Merkle hashing needs no Fq limbs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct MerkleTreeCircuitParams {
    degree: u32,
    lookup_bits: usize,
    num_aggregation: u32,
    num_origin: u32,
}
fn f_from_string<F: BigPrimeField>(s: &str) -> F {
    let bytes: [u8; 32] =
        hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    F::from_bytes_le(&bytes)
}

fn merkle_tree_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    root: F,
    merkle_paths: Vec<&MerklePath>,
) {
    let mut poseidon_chip =
        PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate_chip = GateChip::<F>::default();
    poseidon_chip.initialize_consts(ctx, &gate_chip);
    let merkle_tree_chip = MerkleTreeChip::new(&poseidon_chip, gate_chip);

    let merkle_infos: Vec<MerkleInfo<F>> = merkle_paths
        .iter()
        .map(|path| {
            let sk = f_from_string::<Fr>(&path.sk);
            let stake = f_from_string::<F>(&path.stake);
            let pk = G1Affine::from(G1Affine::generator() * sk);
            let leaf = F::from_bytes_le(&pk.x.to_bytes());
            let path_vals: Vec<F> = path.path.iter().map(|s| f_from_string::<F>(s)).collect();
            let index = path.index.clone();
            MerkleInfo { leaf, stake, path: path_vals, index }
        })
        .collect();

    let result = merkle_tree_chip.merkle_tree_verify_batch(ctx, root, &merkle_infos);
    merkle_tree_chip.gate_chip.assert_is_const(ctx, &result, &F::ONE);
}

#[test]
fn test_merkle_tree() {
    let run_path = "configs/bn254/merkle_tree_circuit.config";
    let path = run_path;
    let params: MerkleTreeCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let merkle_input_path =
        "data/merkle_tree_from_g1_{num}.json".replace("{num}", &params.num_origin.to_string());
    let mut file = File::open(merkle_input_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: MerkleData = serde_json::from_str(&data).expect("Invalid JSON");
    let root = f_from_string::<Fr>(&json_data.root);

    let mut rng = StdRng::seed_from_u64(0xdeadbeef);
    let num_agg = params.num_aggregation as usize;
    assert!(num_agg > 0 && num_agg <= json_data.leaves.len());
    let selected_leaves: Vec<&MerklePath> =
        json_data.leaves.choose_multiple(&mut rng, num_agg).collect();

    base_test().k(params.degree).run(|ctx, _| {
        merkle_tree_test(ctx, root, selected_leaves);
    });
}

#[test]
#[ignore = "run explicitly through the component benchmark runner"]
fn bench_merkle_tree() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::var("HALO2_BENCH_CONFIG")
        .unwrap_or_else(|_| "configs/bn254/bench_merkle_tree.config".into());
    let bench_params_file =
        File::open(&config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();

    let results_path = std::env::var("HALO2_BENCH_OUTPUT")
        .unwrap_or_else(|_| "results/bn254/merkle_tree_bench.csv".into());
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,num_aggregation,num_origin,vk_time_s,pk_time_s,proof_time_s,proof_size_bytes,verify_time_s")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: MerkleTreeCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path = "data/merkle_tree_from_g1_{num}.json"
            .replace("{num}", &bench_params.num_origin.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: MerkleData = serde_json::from_str(&data).expect("Invalid JSON");
        let root = f_from_string::<Fr>(&json_data.root);

        let mut rng = StdRng::seed_from_u64(0xdeadbeef);
        let num_agg = bench_params.num_aggregation as usize;
        assert!(num_agg > 0 && num_agg <= json_data.leaves.len());
        let selected_leaves: Vec<&MerklePath> =
            json_data.leaves.choose_multiple(&mut rng, num_agg).collect();

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (root, selected_leaves.iter().rev().copied().collect::<Vec<_>>()),
            (root, selected_leaves),
            |ctx, _, (root, selected_leaves)| {
                merkle_tree_test(ctx.main(), root, selected_leaves);
            },
        );

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            k,
            stats.config_params.num_advice_per_phase.iter().sum::<usize>(),
            stats.config_params.num_lookup_advice_per_phase.iter().sum::<usize>(),
            stats.config_params.num_fixed,
            stats.config_params.lookup_bits.unwrap_or(0),
            bench_params.num_aggregation,
            bench_params.num_origin,
            stats.vk_time.as_secs_f64(),
            stats.pk_time.as_secs_f64(),
            stats.proof_time.as_secs_f64(),
            stats.proof_size,
            stats.verify_time.as_secs_f64(),
        )?;
    }
    Ok(())
}
