//! Parameterized, explicit real-proof benchmark of the complete inner Certificate.
//! Fixtures and SRS are deterministic testing material, not production secrets/setup.
use crate::bn254::{
    certificate::{
        build_certificate, native_registry_leaf, CertificateParams, CertificateStatement,
        CertificateVote, CertificateWitness,
    },
    eligibility_check::{native_lottery_hash_from_prefix, native_lottery_prefix},
    message_hash::hash_message,
};
use crate::halo2_proofs::{
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        ff::Field,
    },
    plonk::{keygen_pk, keygen_vk},
};
use halo2_base::{
    gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
    utils::{
        biguint_to_fe, fe_to_biguint,
        fs::gen_srs,
        modulus,
        testing::{check_proof_with_instances, gen_proof_with_instances},
    },
};
use rand::{rngs::StdRng, SeedableRng};
use serde::Deserialize;
use std::{
    collections::HashSet,
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
    time::Instant,
};

const CSV_HEADER: &str = "name,degree,lookup_bits,quorum,num_lotteries,num_signers,merkle_depth,target,seed,num_advice,num_lookup_advice,num_fixed,keygen_fixture_s,prover_fixture_s,keygen_build_s,srs_s,vk_s,pk_s,prover_build_s,proof_generation_s,proof_total_s,verify_s,proof_size_bytes";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Target {
    Max,
    Half,
}

impl Target {
    fn as_str(self) -> &'static str {
        match self {
            Self::Max => "max",
            Self::Half => "half",
        }
    }

    fn field(self) -> Fr {
        match self {
            Self::Max => -Fr::ONE,
            Self::Half => biguint_to_fe::<Fr>(&(modulus::<Fr>() / 2u64)),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchConfig {
    name: String,
    degree: u32,
    lookup_bits: usize,
    quorum: usize,
    num_lotteries: u64,
    num_signers: usize,
    merkle_depth: usize,
    target: Target,
    seed: u64,
}

impl BenchConfig {
    fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self.name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err("name must contain 1..=64 ASCII letters, digits, '_' or '-'".into());
        }
        // Explicit harness resource limits, not restrictions of the Certificate protocol.
        if !(10..=24).contains(&self.degree) {
            return Err("benchmark degree must be in 10..=24".into());
        }
        if self.lookup_bits == 0 || self.lookup_bits >= self.degree as usize {
            return Err("lookup_bits must be positive and less than degree".into());
        }
        if self.merkle_depth > 20 {
            return Err("benchmark merkle_depth must be at most 20".into());
        }
        let capacity =
            1usize.checked_shl(self.merkle_depth as u32).ok_or("Merkle capacity overflow")?;
        if self.num_signers == 0 || self.num_signers > capacity {
            return Err("num_signers must be positive and fit the specified Merkle tree".into());
        }
        if self.quorum == 0 || self.quorum > 4096 {
            return Err("benchmark quorum must be in 1..=4096".into());
        }
        if self.num_lotteries == 0 || self.num_lotteries > 1_000_000 {
            return Err("benchmark num_lotteries must be in 1..=1000000".into());
        }
        if u64::try_from(self.quorum).map_err(|_| "quorum overflow")? > self.num_lotteries {
            return Err("quorum must not exceed num_lotteries".into());
        }
        Ok(())
    }

    fn circuit_params(&self) -> CertificateParams {
        CertificateParams {
            quorum: self.quorum,
            num_lotteries: self.num_lotteries,
            merkle_depth: self.merkle_depth,
        }
    }
}

fn hash(values: &[Fr]) -> Fr {
    let mut sponge = poseidon::Poseidon::<Fr, 3, 2>::new(8, 57);
    sponge.update(values);
    sponge.squeeze()
}

fn fixture_rng(seed: u64, domain: u64) -> StdRng {
    let mut material = [0u8; 32];
    material[..8].copy_from_slice(&seed.to_le_bytes());
    material[8..16].copy_from_slice(&domain.to_le_bytes());
    material[16..].copy_from_slice(b"cert-bench-v1\0\0\0");
    StdRng::from_seed(material)
}

struct Registry {
    public_keys: Vec<G1Affine>,
    // Level zero contains leaf hashes; the final level contains the root.
    levels: Vec<Vec<Fr>>,
}

impl Registry {
    fn new(config: &BenchConfig, rng: &mut StdRng) -> Result<(Self, Vec<Fr>), String> {
        config.validate()?;
        let capacity = 1usize << config.merkle_depth;
        let mut secrets = Vec::new();
        secrets.try_reserve_exact(config.num_signers).map_err(|e| e.to_string())?;
        let mut public_keys = Vec::new();
        public_keys.try_reserve_exact(config.num_signers).map_err(|e| e.to_string())?;
        let mut leaves = Vec::new();
        leaves.try_reserve_exact(capacity).map_err(|e| e.to_string())?;
        for _ in 0..config.num_signers {
            let secret = loop {
                let secret = Fr::random(&mut *rng);
                if secret != Fr::ZERO {
                    break secret;
                }
            };
            let public_key = G1Affine::from(G1Affine::generator() * secret);
            // Targets are fixed and authenticated BEFORE computing root, message or signatures.
            leaves.push(native_registry_leaf(&public_key, config.target.field()));
            secrets.push(secret);
            public_keys.push(public_key);
        }
        // Padding is the field zero as a leaf hash, not an extra registered key.
        // Only the first num_signers positions can ever be selected for votes.
        leaves.resize(capacity, Fr::ZERO);
        let mut levels = vec![leaves];
        for _ in 0..config.merkle_depth {
            let previous = levels.last().unwrap();
            let mut parents = Vec::new();
            parents.try_reserve_exact(previous.len() / 2).map_err(|e| e.to_string())?;
            parents.extend(previous.chunks_exact(2).map(hash));
            levels.push(parents);
        }
        Ok((Self { public_keys, levels }, secrets))
    }

    fn root(&self) -> Fr {
        self.levels.last().unwrap()[0]
    }

    fn opening(&self, slot: usize) -> (Vec<Fr>, Vec<bool>) {
        assert!(slot < self.public_keys.len(), "cannot select padding as a signer");
        let mut position = slot;
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut directions = Vec::with_capacity(self.levels.len() - 1);
        for level in self.levels.iter().take(self.levels.len() - 1) {
            path.push(level[position ^ 1]);
            directions.push(position % 2 == 0);
            position /= 2;
        }
        (path, directions)
    }
}

struct Fixture {
    params: CertificateParams,
    statement: CertificateStatement,
    witness: CertificateWitness,
}

fn fixture(config: &BenchConfig, domain: u64) -> Result<Fixture, String> {
    config.validate()?;
    let mut rng = fixture_rng(config.seed, domain);
    let (registry, secrets) = Registry::new(config, &mut rng)?;
    let statement = CertificateStatement {
        registry_root: registry.root(),
        message_digest: Fr::random(&mut rng),
    };
    let message = hash_message(statement.registry_root, statement.message_digest);
    let signatures = secrets
        .iter()
        .take(config.quorum)
        .map(|secret| G2Affine::from(message * secret))
        .collect::<Vec<_>>();
    let prefix = native_lottery_prefix(statement.registry_root, statement.message_digest);
    let target = config.target.field();
    let target_integer = fe_to_biguint(&target);
    let mut next_index =
        if config.target == Target::Max && (config.quorum as u64) < config.num_lotteries {
            1
        } else {
            0
        };
    let mut votes = Vec::with_capacity(config.quorum);
    for vote_position in 0..config.quorum {
        let slot = vote_position % config.num_signers;
        let signature = signatures[slot];
        let lottery_index = loop {
            if next_index >= config.num_lotteries {
                return Err(format!(
                    "{}: domain {domain} found only {} of {} required winning votes in {} indices; increase num_lotteries or choose an explicit different seed/target",
                    config.name, votes.len(), config.quorum, config.num_lotteries
                ));
            }
            let index = next_index;
            next_index += 1;
            let value = native_lottery_hash_from_prefix(prefix, &signature, Fr::from(index));
            if fe_to_biguint(&value) <= target_integer {
                break Fr::from(index);
            }
        };
        let (merkle_path, merkle_directions) = registry.opening(slot);
        votes.push(CertificateVote {
            public_key: registry.public_keys[slot],
            signature,
            target,
            merkle_path,
            merkle_directions,
            lottery_index,
        });
    }
    Ok(Fixture {
        params: config.circuit_params(),
        statement,
        witness: CertificateWitness { votes },
    })
}

fn read_configs(path: &Path) -> Result<Vec<BenchConfig>, Box<dyn Error>> {
    let mut configs = Vec::new();
    let mut names = HashSet::new();
    for (line_number, line) in BufReader::new(File::open(path)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let config: BenchConfig = serde_json::from_str(&line)
            .map_err(|e| format!("{}:{}: {e}", path.display(), line_number + 1))?;
        config.validate().map_err(|e| format!("{}:{}: {e}", path.display(), line_number + 1))?;
        if !names.insert(config.name.clone()) {
            return Err(format!("duplicate benchmark name: {}", config.name).into());
        }
        configs.push(config);
    }
    if configs.is_empty() {
        return Err("benchmark configuration contains no cases".into());
    }
    Ok(configs)
}

#[test]
#[ignore = "explicit full-Certificate real-proof benchmark; use the Certificate runner"]
fn bench_certificate() -> Result<(), Box<dyn Error>> {
    let config_path = std::env::var("HALO2_BENCH_CONFIG")
        .unwrap_or_else(|_| "configs/bn254/bench_certificate.config".into());
    let output_path = std::env::var("HALO2_BENCH_OUTPUT")
        .unwrap_or_else(|_| "results/bn254/certificate_bench.csv".into());
    // Validate the complete input before creating/truncating the output file.
    let configs = read_configs(Path::new(&config_path))?;
    if let Some(parent) = Path::new(&output_path).parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut output = File::create(output_path)?;
    writeln!(output, "{CSV_HEADER}")?;
    output.flush()?;
    for config in configs {
        println!("certificate_benchmark_start {config:?}");
        let started = Instant::now();
        let keygen_fixture = fixture(&config, 1)?;
        let keygen_fixture_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let prover_fixture = fixture(&config, 2)?;
        let prover_fixture_s = started.elapsed().as_secs_f64();
        assert_ne!(keygen_fixture.statement.registry_root, prover_fixture.statement.registry_root);
        assert_ne!(
            keygen_fixture.statement.message_digest,
            prover_fixture.statement.message_digest
        );

        let started = Instant::now();
        let mut keygen = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
            .use_k(config.degree as usize)
            .use_lookup_bits(config.lookup_bits)
            .use_instance_columns(1);
        build_certificate(
            &mut keygen,
            &keygen_fixture.params,
            &keygen_fixture.statement,
            &keygen_fixture.witness,
        );
        let circuit_config = keygen.calculate_params(Some(9));
        let keygen_build_s = started.elapsed().as_secs_f64();
        println!("certificate_circuit_config {circuit_config:?}");
        let num_advice = circuit_config.num_advice_per_phase.iter().sum::<usize>();
        let num_lookup_advice = circuit_config.num_lookup_advice_per_phase.iter().sum::<usize>();
        let num_fixed = circuit_config.num_fixed;
        let started = Instant::now();
        let srs = gen_srs(config.degree);
        let srs_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let vk = keygen_vk(&srs, &keygen)?;
        let vk_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let pk = keygen_pk(&srs, vk, &keygen)?;
        let pk_s = started.elapsed().as_secs_f64();
        let break_points = keygen.break_points();
        drop(keygen);
        drop(keygen_fixture);

        let started = Instant::now();
        let mut prover = RangeCircuitBuilder::prover(circuit_config, break_points);
        build_certificate(
            &mut prover,
            &prover_fixture.params,
            &prover_fixture.statement,
            &prover_fixture.witness,
        );
        let prover_build_s = started.elapsed().as_secs_f64();
        let instances = prover_fixture.statement.instances();
        let started = Instant::now();
        let proof = gen_proof_with_instances(&srs, &pk, prover, &[&instances]);
        let proof_generation_s = started.elapsed().as_secs_f64();
        let proof_total_s = prover_build_s + proof_generation_s;
        let started = Instant::now();
        check_proof_with_instances(&srs, pk.get_vk(), &proof, &[&instances], true);
        let verify_s = started.elapsed().as_secs_f64();
        // Negative checks are outside the successful verification timing.
        let mut wrong_root = instances.clone();
        wrong_root[0] += Fr::ONE;
        check_proof_with_instances(&srs, pk.get_vk(), &proof, &[&wrong_root], false);
        let mut wrong_message = instances;
        wrong_message[1] += Fr::ONE;
        check_proof_with_instances(&srs, pk.get_vk(), &proof, &[&wrong_message], false);

        write!(
            output,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            config.name,
            config.degree,
            config.lookup_bits,
            config.quorum,
            config.num_lotteries,
            config.num_signers,
            config.merkle_depth,
            config.target.as_str(),
            config.seed,
            num_advice,
            num_lookup_advice,
            num_fixed
        )?;
        for seconds in [
            keygen_fixture_s,
            prover_fixture_s,
            keygen_build_s,
            srs_s,
            vk_s,
            pk_s,
            prover_build_s,
            proof_generation_s,
            proof_total_s,
            verify_s,
        ] {
            write!(output, ",{seconds:.9}")?;
        }
        writeln!(output, ",{}", proof.len())?;
        output.flush()?;
        println!("certificate_benchmark_success name={} proof_total_s={proof_total_s:.3} proof_size_bytes={}", config.name, proof.len());
    }
    Ok(())
}

fn test_config() -> BenchConfig {
    BenchConfig {
        name: "regression".into(),
        degree: 18,
        lookup_bits: 16,
        quorum: 5,
        num_lotteries: 64,
        num_signers: 3,
        merkle_depth: 2,
        target: Target::Half,
        seed: 27,
    }
}

#[test]
fn certificate_bench_regression_strict_config_schema_and_bounds() {
    let json = serde_json::json!({"name":"valid", "degree":18, "lookup_bits":16,
        "quorum":3, "num_lotteries":32, "num_signers":5, "merkle_depth":3,
        "target":"half", "seed":0});
    serde_json::from_value::<BenchConfig>(json.clone()).unwrap().validate().unwrap();
    for field in json.as_object().unwrap().keys() {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<BenchConfig>(missing).is_err(), "required {field}");
    }
    let mut unknown = json.clone();
    unknown["unknown"] = serde_json::json!(1);
    assert!(serde_json::from_value::<BenchConfig>(unknown).is_err());
    for (field, value) in [
        ("name", serde_json::json!("bad,name")),
        ("name", serde_json::json!("x".repeat(65))),
        ("degree", serde_json::json!(9)),
        ("degree", serde_json::json!(25)),
        ("lookup_bits", serde_json::json!(0)),
        ("lookup_bits", serde_json::json!(18)),
        ("quorum", serde_json::json!(0)),
        ("quorum", serde_json::json!(4097)),
        ("quorum", serde_json::json!(33)),
        ("num_lotteries", serde_json::json!(0)),
        ("num_lotteries", serde_json::json!(1000001)),
        ("num_signers", serde_json::json!(0)),
        ("num_signers", serde_json::json!(9)),
        ("merkle_depth", serde_json::json!(21)),
        ("target", serde_json::json!("almost")),
        ("seed", serde_json::json!(true)),
    ] {
        let mut invalid = json.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<BenchConfig>(invalid)
                .map(|c| c.validate().is_err())
                .unwrap_or(true),
            "reject {field}"
        );
    }
}

#[test]
fn certificate_bench_regression_registry_padding_and_all_openings() {
    let mut config = test_config();
    config.num_signers = 5;
    config.merkle_depth = 3;
    let (registry, _) = Registry::new(&config, &mut fixture_rng(config.seed, 1)).unwrap();
    assert_eq!(registry.levels[0].len(), 8);
    assert!(registry.levels[0][5..].iter().all(|leaf| *leaf == Fr::ZERO));
    for slot in 0..config.num_signers {
        let mut root = native_registry_leaf(&registry.public_keys[slot], config.target.field());
        assert_eq!(root, registry.levels[0][slot]);
        let (path, directions) = registry.opening(slot);
        for (sibling, left) in path.into_iter().zip(directions) {
            root = if left { hash(&[root, sibling]) } else { hash(&[sibling, root]) };
        }
        assert_eq!(root, registry.root());
    }
    config.num_signers = 1;
    config.merkle_depth = 0;
    let (single, _) = Registry::new(&config, &mut fixture_rng(config.seed, 1)).unwrap();
    assert_eq!(single.root(), native_registry_leaf(&single.public_keys[0], config.target.field()));
    assert_eq!(single.opening(0), (vec![], vec![]));
}

#[test]
fn certificate_bench_regression_deterministic_half_target_fixture() {
    let config = test_config();
    let first = fixture(&config, 1).unwrap();
    let repeat = fixture(&config, 1).unwrap();
    let prover = fixture(&config, 2).unwrap();
    assert_eq!(first.statement.instances(), repeat.statement.instances());
    assert_ne!(first.statement.registry_root, prover.statement.registry_root);
    assert_ne!(first.statement.message_digest, prover.statement.message_digest);
    let prefix =
        native_lottery_prefix(first.statement.registry_root, first.statement.message_digest);
    let mut previous = None;
    for (vote, repeated) in first.witness.votes.iter().zip(&repeat.witness.votes) {
        assert_eq!(vote.public_key, repeated.public_key);
        assert_eq!(vote.signature, repeated.signature);
        assert_eq!(vote.lottery_index, repeated.lottery_index);
        assert_eq!(vote.target, Target::Half.field());
        let mut root = native_registry_leaf(&vote.public_key, vote.target);
        for (sibling, left) in vote.merkle_path.iter().zip(&vote.merkle_directions) {
            root = if *left { hash(&[root, *sibling]) } else { hash(&[*sibling, root]) };
        }
        assert_eq!(root, first.statement.registry_root);
        let value = native_lottery_hash_from_prefix(prefix, &vote.signature, vote.lottery_index);
        assert!(fe_to_biguint(&value) <= fe_to_biguint(&vote.target));
        let index = fe_to_biguint(&vote.lottery_index);
        assert!(index < config.num_lotteries.into());
        if let Some(previous) = previous {
            assert!(index > previous);
        }
        previous = Some(index);
    }
    assert_eq!(first.witness.votes[0].public_key, first.witness.votes[3].public_key);
}

#[test]
fn certificate_bench_regression_max_target_index_boundaries_and_explicit_failure() {
    let mut config = test_config();
    config.target = Target::Max;
    config.num_lotteries = config.quorum as u64;
    let all = fixture(&config, 1).unwrap();
    assert_eq!(all.witness.votes.first().unwrap().lottery_index, Fr::ZERO);
    assert_eq!(all.witness.votes.last().unwrap().lottery_index, Fr::from(config.num_lotteries - 1));
    config.num_lotteries += 1;
    let positive = fixture(&config, 1).unwrap();
    assert_eq!(positive.witness.votes.first().unwrap().lottery_index, Fr::ONE);
    assert_eq!(
        positive.witness.votes.last().unwrap().lottery_index,
        Fr::from(config.quorum as u64)
    );
    config.target = Target::Half;
    config.quorum = 32;
    config.num_lotteries = 32;
    let error = fixture(&config, 1).err().expect("fixed half-target seed cannot fill all 32 slots");
    assert!(error.contains("required winning votes"));
}
