//! Inner BN254 certificate relation with one public registry root and message digest.
//!
//! Every fixed vote slot proves registry membership of `(full public key, target)`,
//! an individual BLS signature on the shared digest-derived message point, and a
//! winning lottery index. All indices are strictly increasing and below a fixed
//! bound. Individual signatures are verified directly, so certificate validity
//! does not depend on a nonzero aggregate or auxiliary MSP weighting witnesses.
//!
//! A verifier must obtain the registry root and circuit parameters from its
//! trusted protocol state. This circuit authenticates a registered threshold;
//! it does not derive that threshold from stake, validate registry construction,
//! or hash original message bytes. The underlying Poseidon-to-BN254 mapping is
//! the experimental suite documented in `message_hash`.

use super::{
    bls_signature::BlsSignatureChip,
    complete_g2::CompleteG2Chip,
    eligibility_check::EligibilityCheckChip,
    index_check::IndexCheckChip,
    merkle_tree::MerkleTreeChip,
    message_hash::MessageHashChip,
    pairing::PairingChip,
    point_encoding::{assigned_g1_encoding, native_g1_encoding},
    FpChip,
};
use crate::{
    ecc::EccChip,
    halo2_proofs::halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        ff::Field,
    },
};
use halo2_base::{
    gates::{circuit::builder::RangeCircuitBuilder, GateChip, GateInstructions, RangeChip},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
};

/// Circuit-shape parameters fixed when generating the verification key.
///
/// Exactly `quorum` votes are supplied. A larger eligible set is represented by
/// choosing `quorum` distinct winning indices and ordering them increasingly.
/// The same registered key may occupy multiple slots with different indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateParams {
    pub quorum: usize,
    /// Valid lottery indices are `0..num_lotteries` (exclusive upper bound).
    pub num_lotteries: u64,
    pub merkle_depth: usize,
}

impl CertificateParams {
    /// Reject impossible shapes before allocating the arithmetic circuit.
    pub fn validate(&self) {
        assert!(self.quorum > 0, "certificate quorum must be nonzero");
        let quorum = u64::try_from(self.quorum).expect("certificate quorum exceeds u64");
        assert!(quorum <= self.num_lotteries, "certificate quorum exceeds lottery count");
    }
}

/// The sole public instance column, in exactly this order: `[root, digest]`.
#[derive(Clone, Copy, Debug)]
pub struct CertificateStatement {
    pub registry_root: Fr,
    pub message_digest: Fr,
}

impl CertificateStatement {
    pub fn instances(&self) -> Vec<Fr> {
        vec![self.registry_root, self.message_digest]
    }
}

#[derive(Clone, Debug)]
pub struct CertificateVote {
    pub public_key: G1Affine,
    pub signature: G2Affine,
    /// Authenticated by the same Merkle leaf as the full public key.
    pub target: Fr,
    pub merkle_path: Vec<Fr>,
    /// `true` places the current hash on the left of the sibling.
    pub merkle_directions: Vec<bool>,
    pub lottery_index: Fr,
}

#[derive(Clone, Debug)]
pub struct CertificateWitness {
    pub votes: Vec<CertificateVote>,
}

/// Registry leaf `Poseidon(EncodeG1(public_key), target)` for the fixed suite.
///
/// `EncodeG1` is eight little-endian 64-bit limbs, four each for canonical x and
/// y. A registry builder is responsible for registering only intended keys and
/// correctly derived targets; this helper does not enforce registration policy.
pub fn native_registry_leaf(public_key: &G1Affine, target: Fr) -> Fr {
    let mut inputs = native_g1_encoding::<Fr>(public_key).to_vec();
    inputs.push(target);
    let mut hasher = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);
    hasher.update(&inputs);
    hasher.squeeze()
}

/// Build the complete inner relation, constraining every acceptance condition.
///
/// The builder must have `k`, lookup bits, and one empty instance column set.
/// All registry, signature and lottery checks consume the same assigned
/// keys, signatures, targets, root and digest. There are no optional vote slots
/// or prover-controlled activity flags. Malformed vector lengths are rejected
/// before circuit construction because they determine the fixed circuit shape.
pub fn build_certificate(
    builder: &mut RangeCircuitBuilder<Fr>,
    params: &CertificateParams,
    statement: &CertificateStatement,
    witness: &CertificateWitness,
) {
    params.validate();
    assert_eq!(witness.votes.len(), params.quorum, "certificate vote count must equal quorum");
    for vote in &witness.votes {
        assert_eq!(vote.merkle_path.len(), params.merkle_depth, "certificate Merkle path depth");
        assert_eq!(
            vote.merkle_directions.len(),
            params.merkle_depth,
            "certificate Merkle direction depth"
        );
    }
    assert!(builder.config_params.k > 0, "certificate builder k must be configured");
    assert_eq!(builder.assigned_instances.len(), 1, "certificate requires one instance column");
    assert!(builder.assigned_instances[0].is_empty(), "certificate instance column must be empty");
    let lookup_bits = builder.lookup_bits().expect("certificate lookup bits must be configured");
    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
    let fp = FpChip::new(&range, 90, 3);
    let pairing = PairingChip::new(&fp);
    let bls = BlsSignatureChip::new(&fp, &pairing);
    let gate = GateChip::default();
    let mut poseidon = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let pool = builder.pool(0);
    let ctx = pool.main();
    poseidon.initialize_consts(ctx, &gate);
    let root = ctx.load_witness(statement.registry_root);
    let digest = ctx.load_witness(statement.message_digest);
    let message = MessageHashChip::new(&fp, &poseidon).hash_assigned(ctx, root, digest);
    let generator = EccChip::new(&fp).assign_constant_point(ctx, G1Affine::generator());
    let lottery = EligibilityCheckChip::new(&poseidon, gate.clone(), &fp);
    let lottery_prefix = lottery.lottery_prefix_assigned(ctx, root, digest);
    let merkle = MerkleTreeChip::new(&poseidon, gate.clone());
    let complete_g2 = CompleteG2Chip::new(&fp);
    let mut indexes = Vec::with_capacity(params.quorum);

    for vote in &witness.votes {
        // These loaders constrain nonidentity points on their respective curves.
        // BN254 G1 has cofactor one; G2 requires the additional integer-r check.
        let key = pairing.load_private_g1(ctx, vote.public_key);
        let signature = pairing.load_private_g2(ctx, vote.signature);
        complete_g2.assert_prime_subgroup(ctx, &signature);
        let target = ctx.load_witness(vote.target);
        let index = ctx.load_witness(vote.lottery_index);

        let mut leaf_inputs = assigned_g1_encoding(ctx, &fp, &key).to_vec();
        leaf_inputs.push(target);
        let leaf = poseidon.hash_fix_len_array(ctx, &gate, &leaf_inputs);
        let path =
            vote.merkle_path.iter().map(|&sibling| ctx.load_witness(sibling)).collect::<Vec<_>>();
        let directions = vote
            .merkle_directions
            .iter()
            .map(|&left| ctx.load_witness(Fr::from(left as u64)))
            .collect::<Vec<_>>();
        let computed_root = merkle.root_from_leaf_hash_assigned(ctx, leaf, &path, &directions);
        ctx.constrain_equal(&computed_root, &root);

        // An aggregate equation alone does not establish validity of every vote.
        let signature_ok = bls.bls_signature_verify_assigned(
            ctx,
            &generator,
            std::slice::from_ref(&signature),
            std::slice::from_ref(&key),
            &message,
        );
        gate.assert_is_const(ctx, &signature_ok, &Fr::ONE);
        let eligible = lottery.eligibility_check_from_prefix_assigned(
            ctx,
            target,
            lottery_prefix,
            &signature,
            index,
        );
        gate.assert_is_const(ctx, &eligible, &Fr::ONE);
        indexes.push(index);
    }

    // The bound is a circuit constant; changing it requires a different key.
    let indexes_ok = IndexCheckChip::new(&range).strict_sorted_bounded_assigned(
        ctx,
        &indexes,
        params.num_lotteries,
    );
    gate.assert_is_const(ctx, &indexes_ok, &Fr::ONE);
    builder.assigned_instances[0] = vec![root, digest];
}
