use halo2_base::{
    gates::{GateChip, GateInstructions},
    poseidon::hasher::PoseidonHasher,
    utils::BigPrimeField,
    AssignedValue, Context,
};

use super::MerkleInfo;

pub struct MerkleTreeChip<'chip, F: BigPrimeField, const T: usize, const RATE: usize> {
    pub poseidon_chip: &'chip PoseidonHasher<F, T, RATE>,
    pub gate_chip: GateChip<F>,
}

impl<'chip, F: BigPrimeField, const T: usize, const RATE: usize> MerkleTreeChip<'chip, F, T, RATE> {
    pub fn new(poseidon_chip: &'chip PoseidonHasher<F, T, RATE>, gate_chip: GateChip<F>) -> Self {
        Self { poseidon_chip, gate_chip }
    }

    /// Compute a root from assigned cells, preserving their bindings to callers.
    /// One places the current hash on the left. Directions are boolean witnesses;
    /// only the path length, not the direction values, determines circuit shape.
    pub fn root_from_assigned(
        &self,
        ctx: &mut Context<F>,
        leaf: AssignedValue<F>,
        stake: AssignedValue<F>,
        path: &[AssignedValue<F>],
        directions: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        let leaf_hash = self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &[leaf, stake]);
        self.root_from_leaf_hash_assigned(ctx, leaf_hash, path, directions)
    }

    /// Opens an already hashed leaf, without adding a second leaf hash. This
    /// lets a certificate commit a complete key and its authenticated target.
    /// One places the current node on the left; zero places it on the right.
    pub fn root_from_leaf_hash_assigned(
        &self,
        ctx: &mut Context<F>,
        leaf_hash: AssignedValue<F>,
        path: &[AssignedValue<F>],
        directions: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        assert_eq!(path.len(), directions.len(), "Merkle path/direction length mismatch");
        let mut hash = leaf_hash;
        for (&sibling, &direction) in path.iter().zip(directions) {
            self.gate_chip.assert_bit(ctx, direction);
            let left = self.gate_chip.select(ctx, hash, sibling, direction);
            let right = self.gate_chip.select(ctx, sibling, hash, direction);
            hash = self.poseidon_chip.hash_fix_len_array(ctx, &self.gate_chip, &[left, right]);
        }
        hash
    }

    pub fn merkle_tree_verify_assigned(
        &self,
        ctx: &mut Context<F>,
        root: AssignedValue<F>,
        leaf: AssignedValue<F>,
        stake: AssignedValue<F>,
        path: &[AssignedValue<F>],
        directions: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        let computed = self.root_from_assigned(ctx, leaf, stake, path, directions);
        self.gate_chip.is_equal(ctx, computed, root)
    }

    fn assign_root(&self, ctx: &mut Context<F>, info: &MerkleInfo<F>) -> AssignedValue<F> {
        let leaf = ctx.load_witness(info.leaf);
        let stake = ctx.load_witness(info.stake);
        let path = info.path.iter().map(|&x| ctx.load_witness(x)).collect::<Vec<_>>();
        let directions =
            info.index.iter().map(|&b| ctx.load_witness(F::from(b as u64))).collect::<Vec<_>>();
        self.root_from_assigned(ctx, leaf, stake, &path, &directions)
    }

    /// Returns an acceptance indicator. Callers must constrain it to one.
    pub fn merkle_tree_verify_one(
        &self,
        ctx: &mut Context<F>,
        root: F,
        merkle_info: MerkleInfo<F>,
    ) -> AssignedValue<F> {
        let computed = self.assign_root(ctx, &merkle_info);
        let root = ctx.load_witness(root);
        self.gate_chip.is_equal(ctx, computed, root)
    }

    /// All openings share one assigned root. Empty batches reject.
    /// This membership component does not enforce a quorum or distinct indices.
    pub fn merkle_tree_verify_batch(
        &self,
        ctx: &mut Context<F>,
        root: F,
        merkle_infos: &[MerkleInfo<F>],
    ) -> AssignedValue<F> {
        if merkle_infos.is_empty() {
            return ctx.load_constant(F::ZERO);
        }
        let root = ctx.load_witness(root);
        let mut result = ctx.load_constant(F::ONE);
        for info in merkle_infos {
            let hash = self.assign_root(ctx, info);
            let valid = self.gate_chip.is_equal(ctx, hash, root);
            result = self.gate_chip.and(ctx, result, valid);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn254::point_encoding::native_g1_encoding;
    use halo2_base::{
        halo2_proofs::halo2curves::{
            bn256::{Fr, G1Affine},
            ff::Field,
        },
        poseidon::hasher::spec::OptimizedPoseidonSpec,
        utils::testing::base_test,
    };

    fn hash(values: &[Fr]) -> Fr {
        let mut hasher = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);
        hasher.update(values);
        hasher.squeeze()
    }

    #[test]
    fn certificate_regression_prehashed_merkle_binds_key_target_and_path() {
        let key = G1Affine::generator();
        let target = Fr::from(17);
        let sibling = Fr::from(42);
        let mut leaf_inputs = native_g1_encoding::<Fr>(&key).to_vec();
        leaf_inputs.push(target);
        let root = hash(&[hash(&leaf_inputs), sibling]);
        for case in 0..7 {
            base_test().k(12).lookup_bits(8).expect_satisfied(case == 0).run(|ctx, _| {
                let gate = GateChip::default();
                let mut hasher =
                    PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
                hasher.initialize_consts(ctx, &gate);
                let chip = MerkleTreeChip::new(&hasher, gate);
                let key = if case == 1 { -key } else { key };
                let mut inputs = native_g1_encoding::<Fr>(&key)
                    .into_iter()
                    .map(|value| ctx.load_witness(value))
                    .collect::<Vec<_>>();
                inputs.push(ctx.load_witness(if case == 2 { target + Fr::ONE } else { target }));
                let leaf_hash = hasher.hash_fix_len_array(ctx, &chip.gate_chip, &inputs);
                let sibling = ctx.load_witness(if case == 3 { sibling + Fr::ONE } else { sibling });
                let direction = ctx.load_witness(match case {
                    4 => Fr::ZERO,
                    6 => Fr::from(2),
                    _ => Fr::ONE,
                });
                let computed =
                    chip.root_from_leaf_hash_assigned(ctx, leaf_hash, &[sibling], &[direction]);
                let root = if case == 5 { root + Fr::ONE } else { root };
                chip.gate_chip.assert_is_const(ctx, &computed, &root);
            });
        }
    }

    #[test]
    fn certificate_regression_prehashed_merkle_empty_path_and_cell_binding() {
        base_test().k(10).lookup_bits(8).run(|ctx, _| {
            let gate = GateChip::default();
            let mut hasher =
                PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
            hasher.initialize_consts(ctx, &gate);
            let chip = MerkleTreeChip::new(&hasher, gate);
            let leaf_hash = ctx.load_witness(Fr::from(7));
            let root = chip.root_from_leaf_hash_assigned(ctx, leaf_hash, &[], &[]);
            chip.gate_chip.assert_is_const(ctx, &root, &Fr::from(7));
        });
        for input in 0..3 {
            base_test().k(11).lookup_bits(8).expect_satisfied(false).run(|ctx, _| {
                let gate = GateChip::default();
                let mut hasher =
                    PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
                hasher.initialize_consts(ctx, &gate);
                let chip = MerkleTreeChip::new(&hasher, gate);
                let cells =
                    [Fr::from(7), Fr::from(42), Fr::ONE].map(|value| ctx.load_witness(value));
                let root =
                    chip.root_from_leaf_hash_assigned(ctx, cells[0], &cells[1..2], &cells[2..]);
                chip.gate_chip.assert_is_const(ctx, &root, &hash(&[Fr::from(7), Fr::from(42)]));
                cells[input].debug_prank(ctx, *cells[input].value() + Fr::ONE);
            });
        }
    }
}
