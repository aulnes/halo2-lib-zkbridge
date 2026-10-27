//! Complete inner-certificate regression fixtures. Targets are committed before
//! deriving the message point or signatures; valid votes are found by a bounded
//! deterministic search, rather than by making the target maximal.
use super::*;
use crate::bn254::{
    certificate::{
        build_certificate, native_registry_leaf, CertificateParams, CertificateStatement,
        CertificateVote, CertificateWitness,
    },
    eligibility_check::{native_lottery_hash_from_prefix, native_lottery_prefix},
    message_hash::hash_message,
};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::{G2Affine, G2},
        ff::Field,
    },
    plonk::{keygen_pk, keygen_vk},
};
use halo2_base::{
    gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
    utils::{
        biguint_to_fe,
        fs::gen_srs,
        modulus,
        testing::{check_proof_with_instances, gen_proof_with_instances},
    },
};
use std::{panic::AssertUnwindSafe, time::Instant};

const K: u32 = 18;
const LOOKUP_BITS: usize = 16;
const NUM_LOTTERIES: u64 = 32;

fn hash(values: &[Fr]) -> Fr {
    let mut sponge = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);
    sponge.update(values);
    sponge.squeeze()
}

fn ordinary_target() -> Fr {
    biguint_to_fe::<Fr>(&(modulus::<Fr>() / 2u64))
}

fn eligible(statement: &CertificateStatement, vote: &CertificateVote, index: u64) -> bool {
    let prefix = native_lottery_prefix(statement.registry_root, statement.message_digest);
    let value = native_lottery_hash_from_prefix(prefix, &vote.signature, Fr::from(index));
    fe_to_biguint(&value) <= fe_to_biguint(&vote.target)
}

#[derive(Clone)]
struct Fixture {
    params: CertificateParams,
    statement: CertificateStatement,
    witness: CertificateWitness,
}

impl Fixture {
    fn new(variant: u64) -> Self {
        Self::with_registry(variant, [0, 2], false)
    }

    /// `zero_first_target` makes the first signer authentically registered with
    /// target zero. Its selected vote is deliberately losing, while its Merkle
    /// path, signature and distinct bounded index all remain valid.
    fn with_registry(variant: u64, signer_slots: [usize; 2], zero_first_target: bool) -> Self {
        Self::with_registry_kind(variant, signer_slots, zero_first_target, false)
    }

    fn with_registry_kind(
        variant: u64,
        signer_slots: [usize; 2],
        zero_first_target: bool,
        antipodal_keys: bool,
    ) -> Self {
        let mut secrets = [11u64, 23, 37, 41].map(|sk| Fr::from(sk + variant));
        if antipodal_keys {
            secrets[2] = -secrets[0];
        }
        let public_keys = secrets.map(|sk| G1Affine::from(G1Affine::generator() * sk));
        let mut targets = [ordinary_target(); 4];
        if zero_first_target {
            targets[signer_slots[0]] = Fr::ZERO;
        }
        // Registry construction must precede H2C: the root enters both H2C and
        // the lottery. Picking a target after observing the lottery would be a
        // circular fixture and would fail to exercise threshold authentication.
        let leaves =
            std::array::from_fn::<_, 4, _>(|i| native_registry_leaf(&public_keys[i], targets[i]));
        let parents = [hash(&leaves[..2]), hash(&leaves[2..])];
        let statement = CertificateStatement {
            registry_root: hash(&parents),
            message_digest: Fr::from(200 + variant),
        };
        let message = hash_message(statement.registry_root, statement.message_digest);
        let mut used = Vec::new();
        let votes = signer_slots
            .into_iter()
            .enumerate()
            .map(|(position, slot)| {
                let mut vote = CertificateVote {
                    public_key: public_keys[slot],
                    signature: G2Affine::from(message * secrets[slot]),
                    target: targets[slot],
                    merkle_path: vec![leaves[slot ^ 1], parents[(slot / 2) ^ 1]],
                    merkle_directions: vec![slot % 2 == 0, slot / 2 == 0],
                    lottery_index: Fr::ZERO,
                };
                let should_win = !(zero_first_target && position == 0);
                let index = (0..NUM_LOTTERIES)
                    .find(|index| {
                        !used.contains(index) && eligible(&statement, &vote, *index) == should_win
                    })
                    .expect("deterministic fixture has an available lottery index");
                used.push(index);
                vote.lottery_index = Fr::from(index);
                vote
            })
            .collect();
        let mut fixture = Self {
            params: CertificateParams { quorum: 2, num_lotteries: NUM_LOTTERIES, merkle_depth: 2 },
            statement,
            witness: CertificateWitness { votes },
        };
        fixture.sort_votes();
        fixture
    }

    fn sort_votes(&mut self) {
        self.witness.votes.sort_by_key(|vote| fe_to_biguint(&vote.lottery_index));
    }

    /// Give each current signature a distinct winning index. Useful after
    /// malicious signature/key changes so lottery rejection does not mask a
    /// failure in the registry/signature relation being tested.
    fn select_winning_indices(&mut self) {
        let mut used = Vec::new();
        for vote in &mut self.witness.votes {
            let index = (0..self.params.num_lotteries)
                .find(|index| !used.contains(index) && eligible(&self.statement, vote, *index))
                .expect("mutated fixture has an available winning index");
            used.push(index);
            vote.lottery_index = Fr::from(index);
        }
        self.sort_votes();
    }
}

fn builder() -> RangeCircuitBuilder<Fr> {
    RangeCircuitBuilder::default()
        .use_k(K as usize)
        .use_lookup_bits(LOOKUP_BITS)
        .use_instance_columns(1)
}

fn mock(fixture: &Fixture, satisfied: bool) {
    let started = Instant::now();
    let mut builder = builder();
    build_certificate(&mut builder, &fixture.params, &fixture.statement, &fixture.witness);
    let config = builder.calculate_params(Some(9));
    let result =
        MockProver::run(K, &builder, vec![fixture.statement.instances()]).unwrap().verify();
    assert_eq!(result.is_ok(), satisfied, "complete certificate satisfaction: {result:?}");
    println!(
        "certificate mock expected={satisfied} seconds={:.3} config={config:?}",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn certificate_regression_valid_two_registered_signers() {
    let fixture = Fixture::new(1);
    assert_ne!(fixture.witness.votes[0].public_key, fixture.witness.votes[1].public_key);
    assert!(fixture.witness.votes.iter().all(|vote| vote.target == ordinary_target()));
    mock(&fixture, true);
}

#[test]
fn certificate_regression_valid_repeated_key_distinct_winning_indices() {
    let fixture = Fixture::with_registry(2, [0, 0], false);
    assert_eq!(fixture.witness.votes[0].public_key, fixture.witness.votes[1].public_key);
    assert_eq!(fixture.witness.votes[0].signature, fixture.witness.votes[1].signature);
    assert_ne!(fixture.witness.votes[0].lottery_index, fixture.witness.votes[1].lottery_index);
    mock(&fixture, true);
}

#[test]
fn certificate_regression_valid_antipodal_registered_keys() {
    let fixture = Fixture::with_registry_kind(4, [0, 2], false, true);
    assert_eq!(fixture.witness.votes[0].public_key, -fixture.witness.votes[1].public_key);
    assert_eq!(fixture.witness.votes[0].signature, -fixture.witness.votes[1].signature);
    // Both signatures are individually valid. A zero aggregate must not make
    // this full certificate fail merely because an optional aggregate gadget
    // cannot represent the identity point.
    mock(&fixture, true);
}

#[test]
fn certificate_regression_rejects_changed_message() {
    let mut fixture = Fixture::new(1);
    fixture.statement.message_digest += Fr::ONE;
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_changed_root() {
    let mut fixture = Fixture::new(1);
    fixture.statement.registry_root += Fr::ONE;
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_key_not_bound_to_its_opening() {
    let mut fixture = Fixture::new(1);
    // Move valid (key, signature) pairs to the other key's authenticated path.
    // Each signature and lottery stays valid; the leaf is wrong.
    let pairs =
        fixture.witness.votes.iter().map(|v| (v.public_key, v.signature)).collect::<Vec<_>>();
    fixture.witness.votes[0].public_key = pairs[1].0;
    fixture.witness.votes[0].signature = pairs[1].1;
    fixture.witness.votes[1].public_key = pairs[0].0;
    fixture.witness.votes[1].signature = pairs[0].1;
    fixture.select_winning_indices();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_bad_signature() {
    let mut fixture = Fixture::new(1);
    fixture.witness.votes[0].signature =
        G2Affine::from(fixture.witness.votes[0].signature * Fr::from(2));
    fixture.select_winning_indices();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_cancelling_invalid_signatures() {
    let mut fixture = Fixture::new(1);
    let original = [fixture.witness.votes[0].signature, fixture.witness.votes[1].signature];
    // D is a nonzero prime-subgroup point. The two errors cancel in an
    // aggregate pairing equation, but neither altered signature is valid for
    // its original registered key and the shared message.
    let delta = G2Affine::generator() * Fr::from(7);
    fixture.witness.votes[0].signature = G2Affine::from(G2::from(original[0]) + delta);
    fixture.witness.votes[1].signature = G2Affine::from(G2::from(original[1]) - delta);
    assert_ne!(fixture.witness.votes[0].signature, original[0]);
    assert_ne!(fixture.witness.votes[1].signature, original[1]);
    assert_eq!(
        G2::from(fixture.witness.votes[0].signature) + fixture.witness.votes[1].signature,
        G2::from(original[0]) + original[1],
        "aggregate signature must remain unchanged"
    );
    // Keep Merkle membership, subgroup checks and lottery eligibility valid so
    // rejection requires enforcing the individual signature relations.
    fixture.select_winning_indices();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_unauthenticated_target_increase() {
    let mut fixture = Fixture::new(1);
    let other_index = fixture.witness.votes[1].lottery_index;
    let losing_index = (0..NUM_LOTTERIES)
        .find(|index| {
            other_index != Fr::from(*index)
                && !eligible(&fixture.statement, &fixture.witness.votes[0], *index)
        })
        .expect("fixture has a losing bounded index");
    fixture.witness.votes[0].lottery_index = Fr::from(losing_index);
    fixture.witness.votes[0].target = -Fr::ONE;
    assert!(eligible(&fixture.statement, &fixture.witness.votes[0], losing_index));
    // Keep the original opening. The larger target makes this ticket eligible
    // but must not be accepted as the target authenticated by the registry.
    fixture.sort_votes();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_authenticated_losing_vote() {
    let fixture = Fixture::with_registry(3, [0, 2], true);
    assert!(fixture.witness.votes.iter().any(|vote| vote.target == Fr::ZERO));
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_tampered_merkle_path() {
    let mut fixture = Fixture::new(1);
    fixture.witness.votes[0].merkle_path[0] += Fr::ONE;
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_tampered_merkle_direction() {
    let mut fixture = Fixture::new(1);
    fixture.witness.votes[0].merkle_directions[0] = !fixture.witness.votes[0].merkle_directions[0];
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_duplicate_winning_index() {
    let mut fixture = Fixture::new(1);
    fixture.witness.votes[1] = fixture.witness.votes[0].clone();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_unsorted_winning_indices() {
    let mut fixture = Fixture::new(1);
    fixture.witness.votes.reverse();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_index_equal_to_lottery_count() {
    let mut fixture = (1..100)
        .map(Fixture::new)
        .find(|f| eligible(&f.statement, &f.witness.votes[0], NUM_LOTTERIES))
        .expect("a fixture is eligible at the excluded upper bound");
    fixture.witness.votes[0].lottery_index = Fr::from(NUM_LOTTERIES);
    fixture.sort_votes();
    mock(&fixture, false);
}

#[test]
fn certificate_regression_rejects_wrong_quorum_and_path_shapes() {
    let fixture = Fixture::new(1);
    for mutation in 0..6 {
        let mut malformed = fixture.clone();
        match mutation {
            0 => {
                malformed.witness.votes.pop();
            }
            1 => malformed.witness.votes.push(malformed.witness.votes[0].clone()),
            2 => {
                malformed.witness.votes[0].merkle_path.pop();
            }
            3 => {
                malformed.witness.votes[0].merkle_directions.pop();
            }
            4 => malformed.params.quorum = 0,
            5 => malformed.params.num_lotteries = 1,
            _ => unreachable!(),
        }
        let rejected = std::panic::catch_unwind(AssertUnwindSafe(|| {
            build_certificate(
                &mut builder(),
                &malformed.params,
                &malformed.statement,
                &malformed.witness,
            );
        }));
        assert!(rejected.is_err(), "malformed certificate shape {mutation} must reject");
    }
}

#[test]
#[ignore = "complete-certificate real-proof smoke; run explicitly with sufficient memory"]
fn certificate_public_inputs_real_proof() {
    let keygen_fixture = Fixture::new(1);
    let prover_fixture = Fixture::new(2);
    assert_ne!(keygen_fixture.statement.registry_root, prover_fixture.statement.registry_root);
    assert_ne!(keygen_fixture.statement.message_digest, prover_fixture.statement.message_digest);
    let mut keygen_builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(K as usize)
        .use_lookup_bits(LOOKUP_BITS)
        .use_instance_columns(1);
    build_certificate(
        &mut keygen_builder,
        &keygen_fixture.params,
        &keygen_fixture.statement,
        &keygen_fixture.witness,
    );
    let config = keygen_builder.calculate_params(Some(9));
    println!(
        "complete certificate params={:?} config={config:?} target={:?}",
        prover_fixture.params,
        fe_to_biguint(&ordinary_target())
    );
    let params = gen_srs(K);
    let started = Instant::now();
    let vk = keygen_vk(&params, &keygen_builder).unwrap();
    let pk = keygen_pk(&params, vk, &keygen_builder).unwrap();
    println!("keygen_seconds={:.3}", started.elapsed().as_secs_f64());
    let break_points = keygen_builder.break_points();
    drop(keygen_builder);
    let started = Instant::now();
    let mut prover = RangeCircuitBuilder::prover(config, break_points);
    build_certificate(
        &mut prover,
        &prover_fixture.params,
        &prover_fixture.statement,
        &prover_fixture.witness,
    );
    let instances = prover_fixture.statement.instances();
    let proof = gen_proof_with_instances(&params, &pk, prover, &[&instances]);
    println!("prove_seconds={:.3} proof_bytes={}", started.elapsed().as_secs_f64(), proof.len());
    let started = Instant::now();
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instances], true);
    println!("verify_seconds={:.3}", started.elapsed().as_secs_f64());
    let mut wrong_root = instances.clone();
    wrong_root[0] += Fr::ONE;
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&wrong_root], false);
    let mut wrong_message = instances;
    wrong_message[1] += Fr::ONE;
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&wrong_message], false);
    println!(
        "different keygen/prover certificates verified; tampered public root and digest rejected"
    );
}
