// Generator for libsignal-derived X3DH vectors.
// Copy into libsignal's rust/protocol/src/bin and run with cargo.
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use sha2::Sha256;

use libsignal_protocol::kem;
use libsignal_protocol::{IdentityKeyPair, KeyPair, KyberPreKeyId, PreKeyId, SignedPreKeyId};

#[derive(Serialize)]
struct X3dhVectorFile {
    cases: Vec<X3dhVectorCase>,
}

#[derive(Serialize)]
struct X3dhVectorCase {
    name: String,
    registration_id: u32,
    device_id: u32,
    initiator: X3dhInitiatorInput,
    responder: X3dhResponderInput,
    expected: X3dhExpectedOutput,
}

#[derive(Serialize)]
struct X3dhInitiatorInput {
    identity_private: String,
    ephemeral_private: String,
}

#[derive(Serialize)]
struct X3dhResponderInput {
    identity_private: String,
    signed_pre_key_id: u32,
    signed_pre_key_private: String,
    signed_pre_key_signature: String,
    pre_key_id: Option<u32>,
    pre_key_private: String,
    kyber_pre_key_id: Option<u32>,
    kyber_public: String,
    kyber_private: String,
    kyber_signature: String,
}

#[derive(Serialize)]
struct X3dhExpectedOutput {
    shared_secret: String,
    initial_chain_key: String,
    associated_data: String,
    kyber_ciphertext: String,
    message_serialized: String,
}

fn main() {
    let vector = build_vector();
    let out = serde_json::to_string_pretty(&vector).expect("json encode");
    println!("{out}");
}

fn build_vector() -> X3dhVectorFile {
    let mut rng_keys = StdRng::from_seed([0x11; 32]);
    let mut rng_sig = StdRng::from_seed([0x22; 32]);
    let mut rng_encap = StdRng::from_seed([0x33; 32]);
    let mut rng_ephemeral = StdRng::from_seed([0x44; 32]);

    let registration_id = 31337u32;
    let device_id = 1u32;
    let signed_pre_key_id: SignedPreKeyId = 5u32.into();
    let pre_key_id: PreKeyId = 7u32.into();
    let kyber_pre_key_id: KyberPreKeyId = 9u32.into();

    let initiator_identity = IdentityKeyPair::generate(&mut rng_keys);
    let responder_identity = IdentityKeyPair::generate(&mut rng_keys);

    let signed_pre_key_pair = KeyPair::generate(&mut rng_keys);
    let pre_key_pair = KeyPair::generate(&mut rng_keys);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng_keys);

    let ephemeral = KeyPair::generate(&mut rng_ephemeral);

    let signed_pre_key_signature = responder_identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut rng_sig)
        .expect("signed pre-key signature");
    let kyber_pre_key_signature = responder_identity
        .private_key()
        .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), &mut rng_sig)
        .expect("kyber pre-key signature");

    let (kyber_ss, kyber_ct) = kyber_pre_key_pair
        .public_key
        .encapsulate(&mut rng_encap)
        .expect("kyber encapsulate");

    let dh1 = initiator_identity
        .private_key()
        .calculate_agreement(&signed_pre_key_pair.public_key)
        .expect("dh1");
    let dh2 = ephemeral
        .private_key
        .calculate_agreement(responder_identity.public_key())
        .expect("dh2");
    let dh3 = ephemeral
        .private_key
        .calculate_agreement(&signed_pre_key_pair.public_key)
        .expect("dh3");
    let dh4 = ephemeral
        .private_key
        .calculate_agreement(&pre_key_pair.public_key)
        .expect("dh4");

    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&dh4);

    let mut ikm_pq = Vec::with_capacity(32 + ikm.len() + kyber_ss.as_ref().len());
    ikm_pq.extend_from_slice(&[0xFFu8; 32]);
    ikm_pq.extend_from_slice(&ikm);
    ikm_pq.extend_from_slice(kyber_ss.as_ref());

    let mut secrets = [0u8; 96];
    let hk = Hkdf::<Sha256>::new(None, &ikm_pq);
    hk.expand(
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024",
        &mut secrets,
    )
    .expect("hkdf expand");

    let shared_secret = &secrets[0..32];
    let initial_chain_key = &secrets[32..64];

    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(&initiator_identity.identity_key().serialize());
    associated_data.extend_from_slice(&responder_identity.identity_key().serialize());

    let mut eph_public = [0u8; 32];
    eph_public.copy_from_slice(ephemeral.public_key.public_key_bytes());

    let initiator_identity_bytes = serialize_identity_key_for_message(&initiator_identity);
    let message_serialized = serialize_x3dh_message(
        &initiator_identity_bytes,
        &eph_public,
        Some(pre_key_id.into()),
        signed_pre_key_id.into(),
        Some((kyber_pre_key_id.into(), kyber_ct.as_ref())),
        &[],
    );

    X3dhVectorFile {
        cases: vec![X3dhVectorCase {
            name: "libsignal-pq-prekey".to_string(),
            registration_id,
            device_id,
            initiator: X3dhInitiatorInput {
                identity_private: hex::encode(initiator_identity.private_key().serialize()),
                ephemeral_private: hex::encode(ephemeral.private_key.serialize()),
            },
            responder: X3dhResponderInput {
                identity_private: hex::encode(responder_identity.private_key().serialize()),
                signed_pre_key_id: signed_pre_key_id.into(),
                signed_pre_key_private: hex::encode(signed_pre_key_pair.private_key.serialize()),
                signed_pre_key_signature: hex::encode(signed_pre_key_signature),
                pre_key_id: Some(pre_key_id.into()),
                pre_key_private: hex::encode(pre_key_pair.private_key.serialize()),
                kyber_pre_key_id: Some(kyber_pre_key_id.into()),
                kyber_public: hex::encode(kyber_pre_key_pair.public_key.serialize()),
                kyber_private: hex::encode(kyber_pre_key_pair.secret_key.serialize()),
                kyber_signature: hex::encode(kyber_pre_key_signature),
            },
            expected: X3dhExpectedOutput {
                shared_secret: hex::encode(shared_secret),
                initial_chain_key: hex::encode(initial_chain_key),
                associated_data: hex::encode(associated_data),
                kyber_ciphertext: hex::encode(kyber_ct.as_ref()),
                message_serialized: hex::encode(message_serialized),
            },
        }],
    }
}

fn serialize_x3dh_message(
    identity: &[u8],
    eph_public: &[u8; 32],
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    kyber: Option<(u32, &[u8])>,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(2u8);
    let identity_len: u16 = identity.len().try_into().expect("identity length");
    out.extend_from_slice(&identity_len.to_be_bytes());
    out.extend_from_slice(identity);
    out.extend_from_slice(eph_public);

    if let Some(pre_key_id) = pre_key_id {
        out.push(1u8);
        out.extend_from_slice(&pre_key_id.to_be_bytes());
    } else {
        out.push(0u8);
        out.extend_from_slice(&0u32.to_be_bytes());
    }

    out.extend_from_slice(&signed_pre_key_id.to_be_bytes());

    if let Some((kyber_id, kyber_ct)) = kyber {
        out.push(1u8);
        out.extend_from_slice(&kyber_id.to_be_bytes());
        out.extend_from_slice(&(kyber_ct.len() as u32).to_be_bytes());
        out.extend_from_slice(kyber_ct);
    } else {
        out.push(0u8);
    }

    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

fn serialize_identity_key_for_message(identity: &IdentityKeyPair) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32);
    out.push(1u8);
    out.extend_from_slice(identity.public_key().public_key_bytes());
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&identity.private_key().serialize());
    let signing_public = xeddsa_signing_public_key(&priv_bytes);
    out.extend_from_slice(&signing_public);
    out
}

fn xeddsa_signing_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *private_key;
    clamp_curve25519_scalar(&mut clamped);
    let scalar = Scalar::from_bytes_mod_order(clamped);
    let ed_public = (&scalar * ED25519_BASEPOINT_TABLE).compress();
    let mut out = [0u8; 32];
    out.copy_from_slice(ed_public.as_bytes());
    out
}

fn clamp_curve25519_scalar(s: &mut [u8; 32]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}
