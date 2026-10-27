//! Public-digest component composition. This deliberately does not claim to
//! verify registry membership, an authenticated target, or a complete certificate.
use super::*;
use crate::bn254::{
    bls_signature::BlsSignatureChip, coordinate_tag::native_coordinate_tag,
    eligibility_check::EligibilityCheckChip, message_hash::hash_message, msp::MspChip,
};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::G2Affine,
    plonk::{keygen_pk, keygen_vk},
};
use halo2_base::{
    gates::{
        circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
        GateChip, GateInstructions,
    },
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{
        fs::gen_srs,
        testing::{check_proof_with_instances, gen_proof_with_instances},
    },
};
use poseidon::Poseidon;
use std::time::Instant;

const K: u32 = 18;
const LOOKUP_BITS: usize = 16;

fn hash(values: &[Fr]) -> Fr {
    let mut h = Poseidon::<Fr, 3, 2>::new(8, 57);
    h.update(values);
    h.squeeze()
}

#[derive(Clone)]
struct Fixture {
    root: Fr,
    msg: Fr,
    signatures: Vec<G2Affine>,
    pubkeys: Vec<G1Affine>,
    seed: Fr,
    ivk: G1Affine,
    isig: G2Affine,
}

impl Fixture {
    fn new(variant: u64) -> Self {
        let root = Fr::from(100 + variant);
        let msg = Fr::from(200 + variant);
        let message = hash_message(root, msg);
        let secrets = [Fr::from(11 + variant)];
        let signatures = secrets.iter().map(|sk| G2Affine::from(message * sk)).collect::<Vec<_>>();
        let pubkeys = secrets.iter().map(|sk| G1Affine::from(G1Affine::generator() * sk)).collect();
        // Historical MSP weighting is unchanged by the message-boundary fix.
        let seed =
            hash(&signatures.iter().map(|p| native_coordinate_tag(&p.x.c0)).collect::<Vec<_>>());
        let weighted_secret = secrets
            .iter()
            .enumerate()
            .fold(Fr::zero(), |acc, (i, sk)| acc + hash(&[Fr::from(i as u64), seed]) * sk);
        Self {
            root,
            msg,
            signatures,
            pubkeys,
            seed,
            ivk: G1Affine::from(G1Affine::generator() * weighted_secret),
            isig: G2Affine::from(message * weighted_secret),
        }
    }

    fn instances(&self) -> Vec<Fr> {
        vec![self.root, self.msg]
    }
}

fn build(builder: &mut RangeCircuitBuilder<Fr>, fixture: &Fixture) {
    let range = RangeChip::new(LOOKUP_BITS, builder.lookup_manager().clone());
    let fp = FpChip::new(&range, 90, 3);
    let pairing = PairingChip::new(&fp);
    let bls = BlsSignatureChip::new(&fp, &pairing);
    let gate = GateChip::default();
    let mut poseidon = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let pool = builder.pool(0);
    let ctx = pool.main();
    poseidon.initialize_consts(ctx, &gate);
    let root = ctx.load_witness(fixture.root);
    let msg = ctx.load_witness(fixture.msg);
    let signatures =
        fixture.signatures.iter().map(|p| pairing.load_private_g2(ctx, *p)).collect::<Vec<_>>();
    let pubkeys =
        fixture.pubkeys.iter().map(|p| pairing.load_private_g1(ctx, *p)).collect::<Vec<_>>();
    let seed = ctx.load_witness(fixture.seed);
    let ivk = pairing.load_private_g1(ctx, fixture.ivk);
    let isig = pairing.load_private_g2(ctx, fixture.isig);
    let result = MspChip::new(&bls, &poseidon).msp_verify_msm_digest_assigned(
        pool,
        root,
        msg,
        &signatures,
        &pubkeys,
        seed,
        &ivk,
        &isig,
    );
    let ctx = pool.main();
    gate.assert_is_const(ctx, &result, &Fr::one());
    let lottery = EligibilityCheckChip::new(&poseidon, gate.clone(), &fp);
    let prefix = lottery.lottery_prefix_assigned(ctx, root, msg);
    for (i, signature) in signatures.iter().enumerate() {
        let index = ctx.load_witness(Fr::from(i as u64));
        // Maximal target keeps this fixture eligible; authenticated targets are
        // outside this component. Separate lottery tests exercise the boundary.
        let target = ctx.load_witness(-Fr::one());
        let eligible =
            lottery.eligibility_check_from_prefix_assigned(ctx, target, prefix, signature, index);
        gate.assert_is_const(ctx, &eligible, &Fr::one());
    }
    // These are exactly the cells consumed by BOTH H2C and the lottery prefix.
    builder.assigned_instances[0] = vec![root, msg];
}

fn mock(fixture: &Fixture, satisfied: bool) {
    let mut builder = RangeCircuitBuilder::default()
        .use_k(K as usize)
        .use_lookup_bits(LOOKUP_BITS)
        .use_instance_columns(1);
    build(&mut builder, fixture);
    builder.calculate_params(Some(9));
    let result = MockProver::run(K, &builder, vec![fixture.instances()]).unwrap().verify();
    assert_eq!(result.is_ok(), satisfied, "public-digest composition satisfaction");
}

#[test]
fn alignment_regression_digest_msp_valid() {
    mock(&Fixture::new(1), true);
}

#[test]
fn alignment_regression_digest_msp_rejects_changed_message() {
    let mut fixture = Fixture::new(1);
    fixture.msg += Fr::one();
    mock(&fixture, false);
}

#[test]
fn alignment_regression_digest_msp_rejects_changed_root() {
    let mut fixture = Fixture::new(1);
    fixture.root += Fr::one();
    mock(&fixture, false);
}

#[test]
#[ignore = "real-proof smoke; run explicitly, not a scaling benchmark"]
fn alignment_public_digest_real_proof() {
    let keygen_fixture = Fixture::new(1);
    let prover_fixture = Fixture::new(2);
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(K as usize)
        .use_lookup_bits(LOOKUP_BITS)
        .use_instance_columns(1);
    build(&mut builder, &keygen_fixture);
    let config = builder.calculate_params(Some(9));
    println!("digest MSP+lottery config: {config:?}");
    let params = gen_srs(K);
    let started = Instant::now();
    let vk = keygen_vk(&params, &builder).unwrap();
    let pk = keygen_pk(&params, vk, &builder).unwrap();
    println!("keygen_seconds={:.3}", started.elapsed().as_secs_f64());
    let break_points = builder.break_points();
    drop(builder);
    let started = Instant::now();
    let mut prover = RangeCircuitBuilder::prover(config, break_points);
    build(&mut prover, &prover_fixture);
    let instances = prover_fixture.instances();
    let proof = gen_proof_with_instances(&params, &pk, prover, &[&instances]);
    println!("prove_seconds={:.3} proof_bytes={}", started.elapsed().as_secs_f64(), proof.len());
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instances], true);
    let mut bad_message = instances.clone();
    bad_message[1] += Fr::one();
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&bad_message], false);
    let mut bad_root = instances;
    bad_root[0] += Fr::one();
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&bad_root], false);
    println!("different keygen/prover witnesses verified; changed public root and msg rejected");
}
