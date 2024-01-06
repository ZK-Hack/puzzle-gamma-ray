use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_mnt4_753::{Fr as MNT4BigFr, MNT4_753};
use ark_mnt6_753::G1Affine;
use ark_mnt6_753::{constraints::G1Var, Fr as MNT6BigFr};

use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};
use ark_crypto_primitives::{crh::TwoToOneCRHScheme, snark::SNARK};
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, Read};

use prompt::{puzzle, welcome};

use std::fs::File;
use std::io::Cursor;

pub mod poseidon_parameters;

type ConstraintF = MNT4BigFr;

use ark_crypto_primitives::{
    crh::{poseidon, *},
    merkle_tree::constraints::*,
    merkle_tree::*,
};
use ark_std::rand::SeedableRng;

type LeafH = poseidon::CRH<ConstraintF>;
type LeafHG = poseidon::constraints::CRHGadget<ConstraintF>;

type CompressH = poseidon::TwoToOneCRH<ConstraintF>;
type CompressHG = poseidon::constraints::TwoToOneCRHGadget<ConstraintF>;

type LeafVar = [FpVar<ConstraintF>];
struct MntMerkleTreeParamsVar;
impl ConfigGadget<MntMerkleTreeParams, ConstraintF> for MntMerkleTreeParamsVar {
    type Leaf = LeafVar;
    type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<ConstraintF>>;
    type InnerDigest = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
    type LeafHash = LeafHG;
    type TwoToOneHash = CompressHG;
}

type MntMerkleTree = MerkleTree<MntMerkleTreeParams>;

struct MntMerkleTreeParams;

impl Config for MntMerkleTreeParams {
    type Leaf = [ConstraintF];

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<ConstraintF>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

#[derive(Clone)]
struct SpendCircuit {
    pub leaf_params: <LeafH as CRHScheme>::Parameters,
    pub two_to_one_params: <LeafH as CRHScheme>::Parameters,
    pub root: <CompressH as TwoToOneCRHScheme>::Output,
    pub proof: Path<MntMerkleTreeParams>,
    pub secret: ConstraintF,
    pub nullifier: ConstraintF,
}

impl ConstraintSynthesizer<ConstraintF> for SpendCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Allocate Merkle Tree Root
        let root = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(
            ark_relations::ns!(cs, "new_digest"),
            || Ok(self.root),
        )?;

        // Allocate Parameters for CRH
        let leaf_crh_params_var =
            <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_parameter"),
                &self.leaf_params,
            )?;
        let two_to_one_crh_params_var =
            <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                &self.two_to_one_params,
            )?;

        let secret = FpVar::new_witness(ark_relations::ns!(cs, "secret"), || Ok(self.secret))?;
        let secret_bits = secret.to_bits_le()?;
        Boolean::enforce_smaller_or_equal_than_le(&secret_bits, MNT6BigFr::MODULUS)?;

        let nullifier = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(
            ark_relations::ns!(cs, "nullifier"),
            || Ok(self.nullifier),
        )?;

        let nullifier_in_circuit =
            <LeafHG as CRHSchemeGadget<LeafH, _>>::evaluate(&leaf_crh_params_var, &[secret])?;
        nullifier_in_circuit.enforce_equal(&nullifier)?;

        let base = G1Var::new_constant(ark_relations::ns!(cs, "base"), G1Affine::generator())?;
        let pk = base.scalar_mul_le(secret_bits.iter())?.to_affine()?;

        // Allocate Leaf
        let leaf_g: Vec<_> = vec![pk.x];

        // Allocate Merkle Tree Path
        let cw: PathVar<MntMerkleTreeParams, ConstraintF, MntMerkleTreeParamsVar> =
            PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&self.proof))?;

        cw.verify_membership(
            &leaf_crh_params_var,
            &two_to_one_crh_params_var,
            &root,
            &leaf_g,
        )?
        .enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

fn from_file<T: CanonicalDeserialize>(path: &str) -> T {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    T::deserialize_uncompressed_unchecked(Cursor::new(&buffer)).unwrap()
}

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);

    let leaves: Vec<Vec<MNT4BigFr>> = from_file("./leaves.bin");
    let leaked_secret: MNT4BigFr = from_file("./leaked_secret.bin");
    let (pk, vk): (
        <Groth16<MNT4_753> as SNARK<MNT4BigFr>>::ProvingKey,
        <Groth16<MNT4_753> as SNARK<MNT4BigFr>>::VerifyingKey,
    ) = from_file("./proof_keys.bin");

    let leaf_crh_params = poseidon_parameters::poseidon_parameters();
    let i = 2;
    let two_to_one_crh_params = leaf_crh_params.clone();

    let nullifier = <LeafH as CRHScheme>::evaluate(&leaf_crh_params, vec![leaked_secret]).unwrap();

    let tree = MntMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        leaves.iter().map(|x| x.as_slice()),
    )
    .unwrap();
    let root = tree.root();
    let leaf = &leaves[i];

    let tree_proof = tree.generate_proof(i).unwrap();
    assert!(tree_proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            leaf.as_slice()
        )
        .unwrap());

    let c = SpendCircuit {
        leaf_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_crh_params.clone(),
        root: root.clone(),
        proof: tree_proof.clone(),
        nullifier: nullifier.clone(),
        secret: leaked_secret.clone(),
    };

    let proof = Groth16::<MNT4_753>::prove(&pk, c.clone(), rng).unwrap();

    assert!(Groth16::<MNT4_753>::verify(&vk, &vec![root, nullifier], &proof).unwrap());

    /* Enter your solution here */

    let nullifier_hack = MNT4BigFr::from(0);
    let secret_hack = MNT4BigFr::from(0);

    /* End of solution */

    assert_ne!(nullifier, nullifier_hack);

    let c2 = SpendCircuit {
        leaf_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_crh_params.clone(),
        root: root.clone(),
        proof: tree_proof.clone(),
        nullifier: nullifier_hack.clone(),
        secret: secret_hack.clone(),
    };

    let proof = Groth16::<MNT4_753>::prove(&pk, c2.clone(), rng).unwrap();

    assert!(Groth16::<MNT4_753>::verify(&vk, &vec![root, nullifier_hack], &proof).unwrap());
}

const PUZZLE_DESCRIPTION: &str = r"
Bob was deeply inspired by the Zcash design [1] for private transactions [2] and had some pretty cool ideas on how to adapt it for his requirements. He was also inspired by the Mina design for the lightest blockchain and wanted to combine the two. In order to achieve that, Bob used the MNT7653 cycle of curves to enable efficient infinite recursion, and used elliptic curve public keys to authorize spends. He released a first version of the system to the world and Alice soon announced she was able to double spend by creating two different nullifiers for the same key... 

[1] https://zips.z.cash/protocol/protocol.pdf
";
