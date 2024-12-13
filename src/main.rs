use ark_bls12_381::{Fr, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::ops::Mul;

fn generate_keys(rng: &mut StdRng) -> (Fr, G2Projective) {
    let sk = Fr::rand(rng);
    let pk = G2Projective::generator().mul(sk);
    (sk, pk)
}

fn main() {
    // this is not suitable for cryptography :)
    let mut rng = StdRng::seed_from_u64(42);

    let (sk1, pk1) = generate_keys(&mut rng);
    let (sk2, pk2) = generate_keys(&mut rng);
    let (sk3, pk3) = generate_keys(&mut rng);

    println!("Secret Keys: {}, {}, {}", sk1, sk2, sk3);
    println!("Public Keys: {:?}, {:?}, {:?}", pk1, pk2, pk3);
}
