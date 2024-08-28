use halo2_base::{halo2_proofs::{
    arithmetic::{CurveAffine, Field}, circuit::{floor_planner::V1, Layouter, Value}, dev::{metadata, FailureLocation, MockProver, VerifyFailure}, halo2curves::{bn256::{Bn256, Fr, G1Affine}, pasta::EqAffine}, plonk::*, poly::{
        commitment::ParamsProver, ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::AccumulatorStrategy,
        }, kzg::{commitment::{KZGCommitmentScheme, ParamsKZG}, multiopen::{ProverSHPLONK, VerifierSHPLONK}, strategy::SingleStrategy}, VerificationStrategy
    }, 
     transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    }
}, utils::fs::gen_srs};
use rand::rngs::StdRng;
use rayon::result;
use crate::{ff::{BatchInvert, FromUniformBytes}, fields::FpStrategy};
use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{io::BufRead, iter, time::Duration};
use std::io::Write;


fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xdeadbeef)
}

#[derive(Clone, Copy, Debug)]
#[derive(serde::Deserialize)]
struct ShuffleCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_aggregation: u32,
}



fn rand_2d_array<F: Field, R: RngCore, const W: usize, const H: usize>(rng: &mut R) -> [[F; H]; W] {
    [(); W].map(|_| [(); H].map(|_| F::random(&mut *rng)))
}

fn shuffled<F: Field, R: RngCore, const W: usize, const H: usize>(
    original: [[F; H]; W],
    rng: &mut R,
) -> [[F; H]; W] {
    let mut shuffled = original;
    // println!("{:?}",original);
    for row in (1..H).rev() {
        let rand_row = (rng.next_u32() as usize) % row;
        for column in shuffled.iter_mut() {
            column.swap(row, rand_row);
        }
    }
    // println!("{:?}",shuffled);
    shuffled
}



#[derive(Clone)]
struct MyConfig<const W: usize> {
    q_shuffle: Selector,
    q_first: Selector,
    q_last: Selector,
    original: [Column<Advice>; W],
    shuffled: [Column<Advice>; W],
    theta: Challenge,
    gamma: Challenge,
    z: Column<Advice>,
}

impl<const W: usize> MyConfig<W> {
    fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let [q_shuffle, q_first, q_last] = [(); 3].map(|_| meta.selector());
        // First phase
        let original = [(); W].map(|_| meta.advice_column_in(FirstPhase));
        let shuffled = [(); W].map(|_| meta.advice_column_in(FirstPhase));
        let [theta, gamma] = [(); 2].map(|_| meta.challenge_usable_after(FirstPhase));
        // Second phase
        let z = meta.advice_column_in(SecondPhase);

        meta.create_gate("z should start with 1", |_| {
            let one = Expression::Constant(F::ONE);

            vec![q_first.expr() * (one - z.cur())]
        });

        meta.create_gate("z should end with 1", |_| {
            let one = Expression::Constant(F::ONE);

            vec![q_last.expr() * (one - z.cur())]
        });

        meta.create_gate("z should have valid transition", |_| {
            let q_shuffle = q_shuffle.expr();
            let original = original.map(|advice| advice.cur());
            let shuffled = shuffled.map(|advice| advice.cur());
            let [theta, gamma] = [theta, gamma].map(|challenge| challenge.expr());

            // Compress
            let original = original
                .iter()
                .cloned()
                .reduce(|acc, a| acc * theta.clone() + a)
                .unwrap();
            let shuffled = shuffled
                .iter()
                .cloned()
                .reduce(|acc, a| acc * theta.clone() + a)
                .unwrap();

            vec![q_shuffle * (z.cur() * (original + gamma.clone()) - z.next() * (shuffled + gamma))]
        });

        Self {
            q_shuffle,
            q_first,
            q_last,
            original,
            shuffled,
            theta,
            gamma,
            z,
        }
    }
}

#[derive(Clone, Default)]
struct MyCircuit<F: Field, const W: usize, const H: usize> {
    original: Value<[[F; H]; W]>,
    shuffled: Value<[[F; H]; W]>,
}

impl<F: Field, const W: usize, const H: usize> MyCircuit<F, W, H> {
    fn rand<R: RngCore>(rng: &mut R) -> Self {
        let original = rand_2d_array::<F, _, W, H>(rng);
        let shuffled = shuffled(original, rng);

        Self {
            original: Value::known(original),
            shuffled: Value::known(shuffled),
        }
    }
}

impl<F: Field, const W: usize, const H: usize> Circuit<F> for MyCircuit<F, W, H> {
    type Config = MyConfig<W>;
    type FloorPlanner = V1;
    // #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MyConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let theta = layouter.get_challenge(config.theta);
        let gamma = layouter.get_challenge(config.gamma);

        layouter.assign_region(
            || "Shuffle original into shuffled",
            |mut region| {
                // Keygen
                config.q_first.enable(&mut region, 0)?;
                config.q_last.enable(&mut region, H)?;
                for offset in 0..H {
                    config.q_shuffle.enable(&mut region, offset)?;
                }

                // First phase
                for (idx, (&column, values)) in config
                    .original
                    .iter()
                    .zip(self.original.transpose_array().iter())
                    .enumerate()
                {
                    for (offset, &value) in values.transpose_array().iter().enumerate() {
                        region.assign_advice(
                            || format!("original[{idx}][{offset}]"),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }
                for (idx, (&column, values)) in config
                    .shuffled
                    .iter()
                    .zip(self.shuffled.transpose_array().iter())
                    .enumerate()
                {
                    for (offset, &value) in values.transpose_array().iter().enumerate() {
                        region.assign_advice(
                            || format!("shuffled[{idx}][{offset}]"),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }

                // Second phase
                let z = self.original.zip(self.shuffled).zip(theta).zip(gamma).map(
                    |(((original, shuffled), theta), gamma)| {
                        let mut product = vec![F::ZERO; H];
                        for (idx, product) in product.iter_mut().enumerate() {
                            let mut compressed = F::ZERO;
                            for value in shuffled.iter() {
                                compressed *= theta;
                                compressed += value[idx];
                            }

                            *product = compressed + gamma
                        }

                        product.iter_mut().batch_invert();

                        for (idx, product) in product.iter_mut().enumerate() {
                            let mut compressed = F::ZERO;
                            for value in original.iter() {
                                compressed *= theta;
                                compressed += value[idx];
                            }

                            *product *= compressed + gamma
                        }

                        #[allow(clippy::let_and_return)]
                        let z = iter::once(F::ONE)
                            .chain(product)
                            .scan(F::ONE, |state, cur| {
                                *state *= &cur;
                                Some(*state)
                            })
                            .collect::<Vec<_>>();

                        // #[cfg(feature = "sanity-checks")]
                        // assert_eq!(F::ONE, *z.last().unwrap());

                        z
                    },
                );
                for (offset, value) in z.transpose_vec(H + 1).into_iter().enumerate() {
                    region.assign_advice(|| format!("z[{offset}]"), config.z, offset, || value)?;
                }

                Ok(())
            },
        )
    }
    
    
}

fn test_mock_prover<F: Ord + FromUniformBytes<64>, const W: usize, const H: usize>(
    k: u32,
    circuit: MyCircuit<F, W, H>,
    expected: Result<(), Vec<(metadata::Constraint, FailureLocation)>>,
) {
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    match (prover.verify(), expected) {
        (Ok(_), Ok(_)) => {}
        (Err(err), Err(expected)) => {
            assert_eq!(
                err.into_iter()
                    .map(|failure| match failure {
                        VerifyFailure::ConstraintNotSatisfied {
                            constraint,
                            location,
                            ..
                        } => (constraint, location),
                        _ => panic!("MockProver::verify has result unmatching expected"),
                    })
                    .collect::<Vec<_>>(),
                expected
            )
        }
        (_, _) => panic!("MockProver::verify has result unmatching expected"),
    };
}
pub fn check_proof(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    instances: &[&[Fr]],
    expect_satisfied: bool,
) {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    let res = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, &[instances], &mut transcript);
    // Just FYI, because strategy is `SingleStrategy`, the output `res` is `Result<(), Error>`, so there is no need to call `res.finalize()`.

    if expect_satisfied {
        res.unwrap();
    } else {
        assert!(res.is_err());
    }
}

struct BenchStats{
    /// Vkey gen time
    pub vk_time: Duration,
    /// Pkey gen time
    pub pk_time: Duration,
    /// Proving time
    pub proof_time: Duration,
    /// Proof size in bytes
    pub proof_size: usize,
    /// Verify time
    pub verify_time: Duration,
}

fn test_prover<C: CurveAffine, const W: usize, const H: usize>(
    k: u32,
    circuit: impl Circuit<Fr>,
    // circuit: MyCircuit<C::Scalar, W, H>,
    expected: bool,
) -> BenchStats
where
    C::Scalar: FromUniformBytes<64>,
{
    // let rng = test_rng();

    let params = gen_srs(k);

    let vk_time = std::time::Instant::now();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let vk_duration = vk_time.elapsed();
    println!("vk_duration: {:?}", vk_duration);

    let pk_time = std::time::Instant::now();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let pk_duration = pk_time.elapsed();
    println!("pk_duration: {:?}", pk_duration);

    let proof_time = std::time::Instant::now();
    let proof = {
        let rng = StdRng::seed_from_u64(0);
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<_>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, _>,
            _,
        >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)
        .expect("prover should not fail");
        transcript.finalize()
    };
    let proof_duration = proof_time.elapsed();
    println!("proof_duration: {:?}", proof_duration);

    let proof_size = proof.len();

    let verify_time = std::time::Instant::now();
    check_proof(&params, pk.get_vk(), &proof, &[], expected);
    let verify_duration = verify_time.elapsed();
    println!("verify_duration: {:?}", verify_duration);


    BenchStats {
        vk_time: vk_duration,
        pk_time: pk_duration,
        proof_time: proof_duration,
        proof_size,
        verify_time: verify_duration,
    }
}

#[test]
fn test_shuffle() {
    const W: usize = 2;
    const H: usize = 1024;
    const K: u32 = 18;

    let config_path = "configs/bn254/shuffle.config";
    let bench_params_file =
        std::fs::File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    let bench_params_reader = std::io::BufReader::new(bench_params_file);

    let results_path = "results/bn254/shuffle_bench.csv";
    let mut fs_results = std::fs::File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_aggregation,proof_time,proof_size,verify_time").unwrap();

    // const H : usize = 2048;

    for line in bench_params_reader.lines() {
        let bench_params: ShuffleCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        // let k = 16;
        

        let circuit = &MyCircuit::<_, W, H>::rand(&mut test_rng());

        test_mock_prover(k, circuit.clone(), Ok(()));

        let proof = test_prover::<EqAffine, W, H>(k, circuit.clone(), true);
        writeln!(
            fs_results,
            "{:?},{},{:?}",
            proof.proof_time,
            proof.proof_size,
            proof.verify_time
        );
        ()
    }

}
