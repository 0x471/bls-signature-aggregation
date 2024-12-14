use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::ops::Mul;

fn generate_keys(rng: &mut StdRng) -> (Fr, G2Projective) {
    let sk = Fr::rand(rng);
    let pk = G2Projective::generator().mul(sk);
    (sk, pk)
}

fn hash_to_g1(message: &[u8]) -> G1Projective {
    let mut hash_value = [0u8; 16];
    let len = hash_value.len().min(message.len());
    hash_value[..len].copy_from_slice(&message[..len]);
    
    let scalar = Fr::from_le_bytes_mod_order(&hash_value);
    G1Projective::generator().mul(scalar)
}

fn sign(message: &[u8], sk: &Fr) -> G1Projective {
    let h = hash_to_g1(message);
    h.mul(sk)
}

fn main() {
    // this is not suitable for cryptography :)
    let mut rng = StdRng::seed_from_u64(42);

    let (sk1, pk1) = generate_keys(&mut rng);
    let (sk2, pk2) = generate_keys(&mut rng);
    let (sk3, pk3) = generate_keys(&mut rng);

    let message1 = b"Hello, Arkworks!";
    let message2 = b"Another message!";
    let message3 = b"Final message!";

    let sig1 = sign(message1, &sk1);
    let sig2 = sign(message2, &sk2);
    let sig3 = sign(message3, &sk3);

    println!("{} {} {}", sig1, sig2, sig3)
}
