use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup, PrimeGroup,
};
use ark_ff::{PrimeField, UniformRand};
use ark_std::{
    rand::{rngs::OsRng, SeedableRng},
    Zero,
};
use std::ops::Mul;

fn generate_keys(rng: &mut impl rand::RngCore) -> (Fr, G2Projective) {
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

fn verify(message: &[u8], signature: &G1Projective, pk: &G2Projective) -> bool {
    let h = hash_to_g1(message);
    Bls12_381::pairing(signature.into_affine(), G2Projective::generator())
        == Bls12_381::pairing(h.into_affine(), pk.into_affine())
}

fn aggregate_signatures(signatures: &[G1Projective]) -> G1Projective {
    signatures
        .iter()
        .fold(G1Projective::zero(), |acc, sig| acc + sig)
}

fn verify_aggregated(
    messages: &[&[u8]],
    aggregated_signature: &G1Projective,
    public_keys: &[G2Projective],
) -> bool {
    let mut pairing_result = PairingOutput::<Bls12_381>::zero();

    for (message, pk) in messages.iter().zip(public_keys.iter()) {
        let h = hash_to_g1(message);
        let pairing = Bls12_381::pairing(h.into_affine(), pk.into_affine());
        pairing_result = pairing_result + pairing;
    }

    let signature_pairing = Bls12_381::pairing(
        aggregated_signature.into_affine(),
        G2Projective::generator(),
    );

    signature_pairing == pairing_result
}
fn main() {
    let mut rng = OsRng;

    let (sk1, pk1) = generate_keys(&mut rng);
    let (sk2, pk2) = generate_keys(&mut rng);
    let (sk3, pk3) = generate_keys(&mut rng);

    let message1 = b"Hello, Arkworks!";
    let message2 = b"Another message!";
    let message3 = b"Final message!";

    let sig1 = sign(message1, &sk1);
    let sig2 = sign(message2, &sk2);
    let sig3 = sign(message3, &sk3);

    assert!(verify(message1, &sig1, &pk1));
    assert!(verify(message2, &sig2, &pk2));
    assert!(verify(message3, &sig3, &pk3));

    let aggregated_signature = aggregate_signatures(&[sig1, sig2, sig3]);

    let messages: Vec<&[u8]> = vec![message1, message2, message3];
    let public_keys = vec![pk1, pk2, pk3];
    assert!(verify_aggregated(
        &messages,
        &aggregated_signature,
        &public_keys
    ));

    println!("All signatures verified successfully!");
}
