//! Deterministic, all-private tests/benchmarks of the prehashed MSP component.
//! Fixtures use the prototype's x.c0 (or x) projection, reduced into Fr; they do
//! not implement secure hash-to-curve, a registry, eligibility, or full STMS.
use super::*;
use crate::bn254::{
    bls_signature::BlsSignatureChip, coordinate_tag::native_coordinate_tag, msp::MspChip,
};
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::{
    gates::{GateChip, GateInstructions},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    Context,
};
use poseidon::Poseidon;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
};

// Column counts are selected by the builder. Legacy strategy/column keys
// remain accepted but ignored when reading older external configs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CombineBlsMtCircuitParams {
    degree: u32,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    num_aggregation: u32,
    num_origin: u32,
}

fn regression_params() -> CombineBlsMtCircuitParams {
    CombineBlsMtCircuitParams {
        degree: 16,
        lookup_bits: 15,
        limb_bits: 90,
        num_limbs: 3,
        num_aggregation: 2,
        num_origin: 4,
    }
}

fn hash(values: &[Fr]) -> Fr {
    let mut hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
    hasher.update(values);
    hasher.squeeze()
}

#[derive(Clone)]
struct MspFixture {
    signatures: Vec<G2Affine>,
    pubkeys: Vec<G1Affine>,
    message: G2Affine,
    seed: Fr,
    ivk: G1Affine,
    isig: G2Affine,
}

impl MspFixture {
    fn new(count: usize, variant: u64) -> Self {
        assert!(count > 0, "MSP needs at least one signer");
        let message = G2Affine::from(G2Affine::generator() * Fr::from(101 + variant));
        let secrets = (0..count).map(|i| Fr::from(11 + variant + 3 * i as u64)).collect::<Vec<_>>();
        let signatures = secrets.iter().map(|sk| G2Affine::from(message * sk)).collect::<Vec<_>>();
        let pubkeys = secrets.iter().map(|sk| G1Affine::from(G1Affine::generator() * sk)).collect();
        let seed = hash(
            &signatures.iter().map(|p| native_coordinate_tag::<Fr>(&p.x.c0)).collect::<Vec<_>>(),
        );
        let weighted_secret = secrets
            .iter()
            .enumerate()
            .fold(Fr::zero(), |acc, (i, sk)| acc + hash(&[Fr::from(i as u64), seed]) * sk);
        Self {
            signatures,
            pubkeys,
            message,
            seed,
            ivk: G1Affine::from(G1Affine::generator() * weighted_secret),
            isig: G2Affine::from(message * weighted_secret),
        }
    }
}

#[derive(Clone)]
struct MspFixture2 {
    signatures: Vec<G1Affine>,
    pubkeys: Vec<G2Affine>,
    message: G1Affine,
    seed: Fr,
    ivk: G2Affine,
    isig: G1Affine,
}

impl MspFixture2 {
    fn new(count: usize, variant: u64) -> Self {
        assert!(count > 0);
        let message = G1Affine::from(G1Affine::generator() * Fr::from(101 + variant));
        let secrets = (0..count).map(|i| Fr::from(11 + variant + 3 * i as u64)).collect::<Vec<_>>();
        let signatures = secrets.iter().map(|sk| G1Affine::from(message * sk)).collect::<Vec<_>>();
        let pubkeys = secrets.iter().map(|sk| G2Affine::from(G2Affine::generator() * sk)).collect();
        let seed =
            hash(&signatures.iter().map(|p| native_coordinate_tag::<Fr>(&p.x)).collect::<Vec<_>>());
        let weighted_secret = secrets
            .iter()
            .enumerate()
            .fold(Fr::zero(), |acc, (i, sk)| acc + hash(&[Fr::from(i as u64), seed]) * sk);
        Self {
            signatures,
            pubkeys,
            message,
            seed,
            ivk: G2Affine::from(G2Affine::generator() * weighted_secret),
            isig: G1Affine::from(message * weighted_secret),
        }
    }
}

fn msp_test(
    pool: &mut SinglePhaseCoreManager<Fr>,
    range: &RangeChip<Fr>,
    params: CombineBlsMtCircuitParams,
    fixture: MspFixture,
    msm: bool,
) {
    let fp_chip = FpChip::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let gate = GateChip::default();
    let mut poseidon = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    poseidon.initialize_consts(pool.main(), &gate);
    let chip = MspChip::new(&bls, &poseidon);
    let result = if msm {
        chip.msp_verify_msm(
            pool,
            G1Affine::generator(),
            &fixture.signatures,
            &fixture.pubkeys,
            fixture.message,
            fixture.seed,
            fixture.ivk,
            fixture.isig,
        )
    } else {
        chip.msp_verify(
            pool.main(),
            G1Affine::generator(),
            &fixture.signatures,
            &fixture.pubkeys,
            fixture.message,
            fixture.seed,
            fixture.ivk,
            fixture.isig,
        )
    };
    gate.assert_is_const(pool.main(), &result, &Fr::one());
}

fn msp_test2(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    params: CombineBlsMtCircuitParams,
    fixture: MspFixture2,
) {
    let fp_chip = FpChip::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let gate = GateChip::default();
    let mut poseidon = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    poseidon.initialize_consts(ctx, &gate);
    let chip = MspChip::new(&bls, &poseidon);
    let result = chip.msp_verify_2(
        ctx,
        G2Affine::generator(),
        &fixture.signatures,
        &fixture.pubkeys,
        fixture.message,
        fixture.seed,
        fixture.ivk,
        fixture.isig,
    );
    gate.assert_is_const(ctx, &result, &Fr::one());
}

fn check_fixture(fixture: MspFixture, msm: bool, satisfied: bool) {
    let params = regression_params();
    base_test()
        .k(params.degree)
        .lookup_bits(params.lookup_bits)
        .expect_satisfied(satisfied)
        .run_builder(|pool, range| {
            msp_test(pool, range, params, fixture, msm);
        });
}

#[test]
fn benchmark_regression_msp_valid_alternate_witnesses() {
    for variant in [1, 2] {
        check_fixture(MspFixture::new(2, variant), true, true);
    }
}

#[test]
fn benchmark_regression_msp_rejects_wrong_seed() {
    let mut fixture = MspFixture::new(2, 1);
    fixture.seed += Fr::one();
    check_fixture(fixture, true, false);
}

#[test]
fn benchmark_regression_msp_rejects_wrong_aggregate_signature() {
    let mut fixture = MspFixture::new(2, 1);
    fixture.isig = G2Affine::from(fixture.isig + fixture.message);
    check_fixture(fixture, true, false);
}

#[test]
fn benchmark_regression_msp_rejects_wrong_aggregate_public_key() {
    let mut fixture = MspFixture::new(2, 1);
    fixture.ivk = G1Affine::from(fixture.ivk + G1Affine::generator());
    check_fixture(fixture, true, false);
}

#[test]
fn benchmark_regression_msp_rejects_different_valid_aggregate() {
    // This substituted pair satisfies the aggregate pairing equation by itself.
    // It must still fail equality with the weighted MSM of the original inputs.
    let mut fixture = MspFixture::new(2, 1);
    fixture.ivk = G1Affine::from(fixture.ivk + G1Affine::generator());
    fixture.isig = G2Affine::from(fixture.isig + fixture.message);
    check_fixture(fixture, true, false);
}

#[test]
fn benchmark_regression_msp_scalar_path() {
    check_fixture(MspFixture::new(2, 1), false, true);
}

#[test]
fn benchmark_regression_msp_inverse_path() {
    let params = regression_params();
    for valid in [true, false] {
        let mut fixture = MspFixture2::new(2, 1);
        if !valid {
            fixture.seed += Fr::one();
        }
        base_test().k(params.degree).lookup_bits(params.lookup_bits).expect_satisfied(valid).run(
            |ctx, range| {
                msp_test2(ctx, range, params, fixture);
            },
        );
    }
}

fn bench_msp_impl(msm: bool, inverse: bool) -> Result<(), Box<dyn std::error::Error>> {
    let default_config =
        if msm { "configs/bn254/bench_msp_msm.config" } else { "configs/bn254/bench_msp.config" };
    let config_path =
        std::env::var("HALO2_BENCH_CONFIG").unwrap_or_else(|_| default_config.to_owned());
    let default_output = if msm {
        "results/bn254/msp_msm_bench.csv"
    } else if inverse {
        "results/bn254/msp_bench2.csv"
    } else {
        "results/bn254/msp_bench.csv"
    };
    let output_path =
        std::env::var("HALO2_BENCH_OUTPUT").unwrap_or_else(|_| default_output.to_owned());
    if let Some(parent) = Path::new(&output_path).parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let configs = BufReader::new(File::open(config_path)?);
    let mut output = File::create(output_path)?;
    writeln!(output, "degree,num_advice,num_lookup_advice,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,num_origin,vk_time_s,pk_time_s,proof_time_s,proof_size_bytes,verify_time_s")?;
    for line in configs.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let params: CombineBlsMtCircuitParams = serde_json::from_str(&line)?;
        assert!(params.num_aggregation > 0 && params.num_aggregation <= params.num_origin);
        let tester = base_test().k(params.degree).lookup_bits(params.lookup_bits);
        let stats = if inverse {
            tester.bench_builder(
                MspFixture2::new(params.num_aggregation as usize, 1),
                MspFixture2::new(params.num_aggregation as usize, 2),
                |pool, range, fixture| {
                    msp_test2(pool.main(), range, params, fixture);
                },
            )
        } else {
            tester.bench_builder(
                MspFixture::new(params.num_aggregation as usize, 1),
                MspFixture::new(params.num_aggregation as usize, 2),
                |pool, range, fixture| {
                    msp_test(pool, range, params, fixture, msm);
                },
            )
        };
        writeln!(
            output,
            "{},{},{},{},{},{},{},{},{},{:.9},{:.9},{:.9},{},{:.9}",
            stats.config_params.k,
            stats.config_params.num_advice_per_phase.iter().sum::<usize>(),
            stats.config_params.num_lookup_advice_per_phase.iter().sum::<usize>(),
            stats.config_params.num_fixed,
            stats.config_params.lookup_bits.unwrap_or(0),
            params.limb_bits,
            params.num_limbs,
            params.num_aggregation,
            params.num_origin,
            stats.vk_time.as_secs_f64(),
            stats.pk_time.as_secs_f64(),
            stats.proof_time.as_secs_f64(),
            stats.proof_size,
            stats.verify_time.as_secs_f64()
        )?;
        output.flush()?;
    }
    Ok(())
}

#[test]
#[ignore = "explicit real-proof component benchmark; use the benchmark runner"]
fn bench_msp() -> Result<(), Box<dyn std::error::Error>> {
    bench_msp_impl(false, false)
}

#[test]
#[ignore = "explicit real-proof component benchmark; use the benchmark runner"]
fn bench2_msp() -> Result<(), Box<dyn std::error::Error>> {
    bench_msp_impl(false, true)
}

#[test]
#[ignore = "explicit real-proof component benchmark; use the benchmark runner"]
fn bench_msp_msm() -> Result<(), Box<dyn std::error::Error>> {
    bench_msp_impl(true, false)
}
