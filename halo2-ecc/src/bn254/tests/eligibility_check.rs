#![allow(non_snake_case)]
use super::*;
use crate::bn254::{
    coordinate_tag::native_coordinate_tag, eligibility_check::EligibilityCheckChip,
    pairing::PairingChip,
};
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bn256::{Fq, G2Affine};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::ff::{Field, PrimeField};
use halo2_base::utils::{biguint_to_fe, modulus, BigPrimeField};
use halo2_base::Context;
use halo2_base::{
    gates::GateChip,
    halo2_proofs::arithmetic::CurveAffine,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct g2_struct {
    x_c0: String,
    x_c1: String,
    y_c0: String,
    y_c1: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EligibilityData {
    phi_stakes: Vec<String>,
    signatures: Vec<g2_struct>,
    msghash: String,
    indexes: Vec<String>,
}

// Column counts are selected by the builder. Legacy strategy/column keys
// remain accepted but ignored when reading older external configs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct EligibilityCheckCircuitParams {
    degree: u32,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    num: u32,
}

fn f_from_string<F: BigPrimeField>(s: &str) -> F {
    let bytes: [u8; 32] =
        hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    F::from_bytes_le(&bytes)
}
fn fr_from_string(s: &str) -> Fr {
    let bytes: [u8; 32] =
        hex::decode(s).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fr::from_bytes(&bytes).unwrap();
    result
}
fn fq2_from_string(c0: &str, c1: &str) -> Fq2 {
    let c0_bytes: [u8; 32] =
        hex::decode(c0).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let c1_bytes: [u8; 32] =
        hex::decode(c1).expect("Invalid hex string").try_into().expect("Invalid Fr bytes");
    let result = Fq2::new(Fq::from_bytes(&c0_bytes).unwrap(), Fq::from_bytes(&c1_bytes).unwrap());
    result
}

fn g2_from_string(s: g2_struct) -> G2Affine {
    G2Affine::from_xy(fq2_from_string(&s.x_c0, &s.x_c1), fq2_from_string(&s.y_c0, &s.y_c1)).unwrap()
}

fn eligibility_check_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: EligibilityCheckCircuitParams,
    phi_stakes: &[F],
    signatures: &[G2Affine],
    msghash: G2Affine,
    indexes: &[F],
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let mut poseidon_chip =
        PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate_chip = GateChip::<F>::default();
    poseidon_chip.initialize_consts(ctx, &gate_chip);

    let eligibility_check_chip = EligibilityCheckChip::new(&poseidon_chip, gate_chip, &fp_chip);

    let result = eligibility_check_chip
        .eligibility_check_batch(ctx, phi_stakes, signatures, msghash, indexes);

    range.gate().assert_is_const(ctx, &result, &F::ONE);
}

#[test]
fn test_eligibility_check() {
    let run_path = "configs/bn254/eligibility_check.config";
    let path = run_path;
    let params: EligibilityCheckCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let eligibility_info_path =
        "data/data_for_eligibility_{num}.json".replace("{num}", &params.num.to_string());
    let mut file = File::open(eligibility_info_path).expect("Unable to open file");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read file");

    let json_data: EligibilityData = serde_json::from_str(&data).expect("Invalid JSON");

    let msg_hash = json_data.msghash.clone();
    let msg_hash_to_fr = fr_from_string(&msg_hash);
    let msghash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);
    let signatures = json_data.signatures.iter().map(|x| g2_from_string(x.clone())).collect_vec();
    let indexes = json_data.indexes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();
    let phi_stakes =
        json_data.phi_stakes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        eligibility_check_test(ctx, range, params, &phi_stakes, &signatures, msghash, &indexes);
    });
}

#[test]
#[ignore = "run explicitly through the component benchmark runner"]
fn bench_eligibility_check() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::var("HALO2_BENCH_CONFIG")
        .unwrap_or_else(|_| "configs/bn254/bench_eligibility_check.config".to_owned());
    let bench_params_file =
        File::open(&config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();

    let results_path = std::env::var("HALO2_BENCH_OUTPUT")
        .unwrap_or_else(|_| "results/bn254/eligibility_bench.csv".to_owned());
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,native_limb_bits,native_num_limbs,num,vk_time_s,pk_time_s,proof_time_s,proof_size_bytes,verify_time_s")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: EligibilityCheckCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let merkle_input_path =
            "data/data_for_eligibility_{num}.json".replace("{num}", &bench_params.num.to_string());
        let mut file = File::open(merkle_input_path).expect("Unable to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Unable to read file");

        let json_data: EligibilityData = serde_json::from_str(&data).expect("Invalid JSON");
        let msg_hash = json_data.msghash.clone();
        let msg_hash_to_fr = fr_from_string(&msg_hash);
        let msghash = G2Affine::from(G2Affine::generator() * msg_hash_to_fr);
        let signatures =
            json_data.signatures.iter().map(|x| g2_from_string(x.clone())).collect_vec();
        let indexes =
            json_data.indexes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();
        let phi_stakes =
            json_data.phi_stakes.iter().map(|x| f_from_string::<Fr>(&x.clone())).collect_vec();

        assert_eq!(phi_stakes.len(), bench_params.num as usize, "fixture batch size");
        let mut keygen_signatures = signatures.clone();
        let mut keygen_indexes = indexes.clone();
        let mut keygen_targets = phi_stakes.clone();
        keygen_signatures.reverse();
        keygen_indexes.reverse();
        keygen_targets.reverse();
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (msghash, keygen_signatures, keygen_indexes, keygen_targets),
            (msghash, signatures, indexes, phi_stakes),
            |ctx, range, (msghash, signatures, indexes, phi_stakes)| {
                eligibility_check_test(
                    ctx.main(),
                    range,
                    bench_params,
                    &phi_stakes,
                    &signatures,
                    msghash,
                    &indexes,
                );
            },
        );

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            k,
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
fn native_eligibility_hash(message: Fr, index: Fr, signature: Fr) -> Fr {
    let mut sponge = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);
    sponge.update(&[Fr::ONE, message, index, signature]);
    sponge.squeeze()
}

fn assigned_eligibility_test(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    values: (Fr, Fr, Fr, Fr),
) -> [halo2_base::AssignedValue<Fr>; 4] {
    let fp = FpChip::<Fr>::new(range, 90, 3);
    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, range.gate());
    let chip = EligibilityCheckChip::new(&hasher, GateChip::default(), &fp);
    let (target, message, index, signature) = values;
    let target = ctx.load_witness(target);
    let message = ctx.load_witness(message);
    let index = ctx.load_witness(index);
    let signature = ctx.load_witness(signature);
    let result = chip.eligibility_check_assigned(ctx, target, signature, message, index);
    range.gate().assert_is_const(ctx, &result, &Fr::ONE);
    [target, message, index, signature]
}

#[test]
fn benchmark_regression_eligibility_threshold_bounds() {
    let message = Fr::from(2);
    let index = Fr::from(3);
    let signature = Fr::from(4);
    let hash = native_eligibility_hash(message, index, signature);
    assert_ne!(hash, Fr::ZERO);
    assert_ne!(hash, -Fr::ONE);
    for (target, valid) in [
        (hash, true),
        (hash + Fr::ONE, true),
        (hash - Fr::ONE, false),
        (Fr::ZERO, false),
        (-Fr::ONE, true),
    ] {
        base_test().k(12).lookup_bits(8).expect_satisfied(valid).run(|ctx, range| {
            assigned_eligibility_test(ctx, range, (target, message, index, signature));
        });
    }
}

#[test]
fn benchmark_regression_eligibility_input_binding() {
    let message = Fr::from(2);
    let index = Fr::from(3);
    let signature = Fr::from(4);
    let hash = native_eligibility_hash(message, index, signature);
    for tampered in 0..4 {
        base_test().k(12).lookup_bits(8).expect_satisfied(false).run(|ctx, range| {
            let cells = assigned_eligibility_test(ctx, range, (hash, message, index, signature));
            cells[tampered].debug_prank(ctx, *cells[tampered].value() + Fr::ONE);
        });
    }
}

#[test]
fn benchmark_regression_eligibility_changed_witnesses_same_key() {
    let first = (Fr::from(2), Fr::from(3), Fr::from(4));
    let second = (-Fr::from(2), -Fr::ONE, Fr::from(5));
    base_test().k(12).lookup_bits(8).bench_builder(
        (native_eligibility_hash(first.0, first.1, first.2), first.0, first.1, first.2),
        (native_eligibility_hash(second.0, second.1, second.2), second.0, second.1, second.2),
        |pool, range, values| {
            assigned_eligibility_test(pool.main(), range, values);
        },
    );
}

#[test]
fn benchmark_regression_eligibility_batch_shares_message() {
    for tamper in [false, true] {
        base_test().k(12).lookup_bits(8).expect_satisfied(!tamper).run(|ctx, range| {
            let fp = FpChip::<Fr>::new(range, 90, 3);
            let mut hasher =
                PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
            hasher.initialize_consts(ctx, range.gate());
            let chip = EligibilityCheckChip::new(&hasher, GateChip::default(), &fp);
            let message_value = Fr::from(2);
            let message = ctx.load_witness(message_value);
            let mut targets = Vec::new();
            let mut signatures = Vec::new();
            let mut indexes = Vec::new();
            for index in [Fr::from(3), Fr::from(4)] {
                let signature = Fr::from(5);
                targets.push(ctx.load_witness(native_eligibility_hash(
                    message_value,
                    index,
                    signature,
                )));
                signatures.push(ctx.load_witness(signature));
                indexes.push(ctx.load_witness(index));
            }
            let result = chip.eligibility_check_batch_assigned(
                ctx,
                &targets,
                &signatures,
                message,
                &indexes,
            );
            range.gate().assert_is_const(ctx, &result, &Fr::ONE);
            // Each row must copy the same source cell into its hash. Simply
            // reloading its host value into fresh witnesses loses this binding.
            let message_cell = message.cell.unwrap();
            let uses = ctx
                .copy_manager
                .lock()
                .unwrap()
                .advice_equalities
                .iter()
                .filter(|(a, b)| *a == message_cell || *b == message_cell)
                .count();
            assert!(uses >= indexes.len(), "every row must be bound to the shared message");
            if tamper {
                message.debug_prank(ctx, message_value + Fr::ONE);
            }
        });
    }
}

fn assigned_coordinate_eligibility_test(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    values: (Fr, Fq, Fq),
) {
    let fp = FpChip::<Fr>::new(range, 90, 3);
    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, range.gate());
    let chip = EligibilityCheckChip::new(&hasher, GateChip::default(), &fp);
    let (target, message, signature) = values;
    let target = ctx.load_witness(target);
    let message = fp.load_private(ctx, message);
    let signature = fp.load_private(ctx, signature);
    let index = ctx.load_witness(Fr::from(7));
    let result =
        chip.eligibility_check_coordinates_assigned(ctx, target, &signature, &message, index);
    range.gate().assert_is_const(ctx, &result, &Fr::ONE);
}

#[test]
fn benchmark_regression_eligibility_coordinate_tag_boundaries() {
    let r = modulus::<Fr>();
    let q = modulus::<Fq>();
    // These are raw coordinates, so the conversion test does not pretend that
    // artificial boundary values form valid curve points.
    let cases = [
        (0u64.into(), Fr::ZERO),
        (&r - 1u64, -Fr::ONE),
        (r.clone(), Fr::ZERO),
        (&r + 1u64, Fr::ONE),
        (&q - 1u64, biguint_to_fe::<Fr>(&(&q - &r - 1u64))),
    ];
    for (i, (message, message_tag)) in cases.iter().enumerate() {
        let (signature, signature_tag) = &cases[(i + 1) % cases.len()];
        let hash = native_eligibility_hash(*message_tag, Fr::from(7), *signature_tag);
        assert_ne!(hash, Fr::ZERO);
        for (target, valid) in [(hash, true), (hash - Fr::ONE, false)] {
            base_test().k(12).lookup_bits(8).expect_satisfied(valid).run(|ctx, range| {
                assigned_coordinate_eligibility_test(
                    ctx,
                    range,
                    (target, biguint_to_fe(message), biguint_to_fe(signature)),
                );
            });
        }
    }
}

#[test]
fn benchmark_regression_eligibility_coordinate_tags_changed_witnesses_same_key() {
    let r = modulus::<Fr>();
    let q = modulus::<Fq>();
    let first = (biguint_to_fe::<Fq>(&(&r - 1u64)), Fq::from(42));
    let second = (biguint_to_fe::<Fq>(&(&r + 1u64)), biguint_to_fe::<Fq>(&(&q - 1u64)));
    let with_target = |(message, signature): (Fq, Fq)| {
        let target = native_eligibility_hash(
            native_coordinate_tag(&message),
            Fr::from(7),
            native_coordinate_tag(&signature),
        );
        (target, message, signature)
    };
    base_test().k(12).lookup_bits(8).bench_builder(
        with_target(first),
        with_target(second),
        |pool, range, values| {
            assigned_coordinate_eligibility_test(pool.main(), range, values);
        },
    );
}

#[test]
fn benchmark_regression_eligibility_assigned_point_adapter() {
    let signature = G2Affine::from(G2Affine::generator() * Fr::from(11));
    let message = G2Affine::from(G2Affine::generator() * Fr::from(13));
    let index_value = Fr::from(7);
    let target_value = native_eligibility_hash(
        native_coordinate_tag(&message.x.c0),
        index_value,
        native_coordinate_tag(&signature.x.c0),
    );
    base_test().k(12).lookup_bits(8).run(|ctx, range| {
        let fp = FpChip::<Fr>::new(range, 90, 3);
        let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
        hasher.initialize_consts(ctx, range.gate());
        let chip = EligibilityCheckChip::new(&hasher, GateChip::default(), &fp);
        let pairing = PairingChip::new(&fp);
        let assigned_signature = pairing.load_private_g2(ctx, signature);
        let assigned_message = pairing.load_private_g2(ctx, message);
        let target = ctx.load_witness(target_value);
        let index = ctx.load_witness(index_value);
        let assigned_result = chip.eligibility_check_points_assigned(
            ctx,
            target,
            &assigned_signature,
            &assigned_message,
            index,
        );
        let native_result =
            chip.eligibility_check_one(ctx, target_value, signature, message, index_value);
        range.gate().assert_is_const(ctx, &assigned_result, &Fr::ONE);
        range.gate().assert_is_const(ctx, &native_result, &Fr::ONE);
    });
}
