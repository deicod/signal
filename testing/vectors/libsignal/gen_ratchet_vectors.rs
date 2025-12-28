// Generator for libsignal-derived Double Ratchet vectors.
// Copy into libsignal's rust/protocol/src/bin and run with cargo.
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use sha2::Sha256;

use libsignal_protocol::kem;
use libsignal_protocol::{IdentityKeyPair, KeyPair, KyberPreKeyId, PreKeyId, SignedPreKeyId};
use libsignal_protocol::{PrivateKey, PublicKey};
use signal_crypto::Aes256GcmEncryption;

#[derive(Serialize)]
struct RatchetVectorFile {
    name: String,
    x3dh: RatchetX3dhInput,
    associated_data: String,
    initiator_messages: Vec<RatchetVectorMsg>,
    responder_messages: Vec<RatchetVectorMsg>,
    delivery_to_responder: Vec<u32>,
    delivery_to_initiator: Vec<u32>,
}

#[derive(Serialize)]
struct RatchetX3dhInput {
    initiator: X3dhInitiatorInput,
    responder: X3dhResponderInput,
    responder_send_private: String,
    shared_secret: String,
    kyber_ciphertext: String,
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
struct RatchetVectorMsg {
    plaintext: String,
    header: String,
    ciphertext: String,
}

fn main() {
    let vector = build_vector();
    let out = serde_json::to_string_pretty(&vector).expect("json encode");
    println!("{out}");
}

fn build_vector() -> RatchetVectorFile {
    let mut rng_keys = StdRng::from_seed([0xA1; 32]);
    let mut rng_sig = StdRng::from_seed([0xB2; 32]);
    let mut rng_encap = StdRng::from_seed([0xC3; 32]);
    let mut rng_ephemeral = StdRng::from_seed([0xD4; 32]);
    let mut rng_send = StdRng::from_seed([0xE5; 32]);

    let signed_pre_key_id: SignedPreKeyId = 21u32.into();
    let pre_key_id: PreKeyId = 22u32.into();
    let kyber_pre_key_id: KyberPreKeyId = 23u32.into();

    let initiator_identity = IdentityKeyPair::generate(&mut rng_keys);
    let responder_identity = IdentityKeyPair::generate(&mut rng_keys);

    let signed_pre_key_pair = KeyPair::generate(&mut rng_keys);
    let pre_key_pair = KeyPair::generate(&mut rng_keys);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng_keys);

    let ephemeral = KeyPair::generate(&mut rng_ephemeral);
    let send_dh = KeyPair::generate(&mut rng_send);

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

    let mut shared_secret = [0u8; 32];
    let mut initial_chain_key = [0u8; 32];
    shared_secret.copy_from_slice(&secrets[0..32]);
    initial_chain_key.copy_from_slice(&secrets[32..64]);

    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(&initiator_identity.identity_key().serialize());
    associated_data.extend_from_slice(&responder_identity.identity_key().serialize());

    let mut init_state = init_initiator_state(
        shared_secret,
        initial_chain_key,
        send_dh.clone(),
        signed_pre_key_pair.public_key,
    );
    let mut resp_state = init_responder_state(
        shared_secret,
        initial_chain_key,
        signed_pre_key_pair.clone(),
        public_key_from_bytes(ephemeral.public_key.public_key_bytes()),
    );

    let initiator_plaintexts = [b"alice-1".as_slice(), b"alice-2".as_slice(), b"alice-3".as_slice()];
    let responder_plaintexts = [b"bob-1".as_slice()];

    let mut initiator_messages = Vec::new();
    for plaintext in initiator_plaintexts.iter() {
        let msg = init_state.encrypt(plaintext, &associated_data);
        initiator_messages.push(msg);
    }

    let mut responder_messages = Vec::new();
    for plaintext in responder_plaintexts.iter() {
        let msg = resp_state.encrypt(plaintext, &associated_data);
        responder_messages.push(msg);
    }

    RatchetVectorFile {
        name: "libsignal-pq-ratchet".to_string(),
        x3dh: RatchetX3dhInput {
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
            responder_send_private: hex::encode(send_dh.private_key.serialize()),
            shared_secret: hex::encode(shared_secret),
            kyber_ciphertext: hex::encode(kyber_ct.as_ref()),
        },
        associated_data: hex::encode(associated_data),
        initiator_messages,
        responder_messages,
        delivery_to_responder: vec![1, 0, 2],
        delivery_to_initiator: vec![0],
    }
}

#[derive(Clone)]
struct RatchetState {
    dhs: KeyPair,
    rk: [u8; 32],
    cks: [u8; 32],
    ckr: [u8; 32],
    ns: u32,
    nr: u32,
    pn: u32,
}

impl RatchetState {
    fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> RatchetVectorMsg {
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(self.dhs.public_key.public_key_bytes());
        let header = Header {
            dh: dh_bytes,
            pn: self.pn,
            n: self.ns,
        };

        let (new_cks, mk) = kdf_chain(&self.cks);
        self.cks = new_cks;
        self.ns = self.ns.wrapping_add(1);

        let (enc_key, _auth_key, iv) = derive_message_keys(&mk);
        let nonce = &iv[..12];

        let mut ad = Vec::with_capacity(associated_data.len() + 40);
        ad.extend_from_slice(associated_data);
        ad.extend_from_slice(&header.serialize());

        let mut buf = plaintext.to_vec();
        let mut gcm = Aes256GcmEncryption::new(&enc_key, nonce, &ad).expect("gcm init");
        gcm.encrypt(&mut buf);
        let tag = gcm.compute_tag();

        let mut ciphertext = Vec::with_capacity(12 + buf.len() + tag.len());
        ciphertext.extend_from_slice(nonce);
        ciphertext.extend_from_slice(&buf);
        ciphertext.extend_from_slice(&tag);

        RatchetVectorMsg {
            plaintext: hex::encode(plaintext),
            header: hex::encode(header.serialize()),
            ciphertext: hex::encode(ciphertext),
        }
    }
}

#[derive(Clone)]
struct Header {
    dh: [u8; 32],
    pn: u32,
    n: u32,
}

impl Header {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.dh);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out
    }
}

fn init_initiator_state(
    shared_secret: [u8; 32],
    initial_chain_key: [u8; 32],
    dhs: KeyPair,
    dhr: PublicKey,
) -> RatchetState {
    let mut state = RatchetState {
        dhs,
        rk: shared_secret,
        cks: [0u8; 32],
        ckr: initial_chain_key,
        ns: 0,
        nr: 0,
        pn: 0,
    };

    let dh_out = dh(&state.dhs.private_key, &dhr);
    let (new_rk, new_cks) = kdf_root(&state.rk, &dh_out);
    state.rk = new_rk;
    state.cks = new_cks;

    state
}

fn init_responder_state(
    shared_secret: [u8; 32],
    initial_chain_key: [u8; 32],
    dhs: KeyPair,
    _dhr: PublicKey,
) -> RatchetState {
    RatchetState {
        dhs,
        rk: shared_secret,
        cks: initial_chain_key,
        ckr: [0u8; 32],
        ns: 0,
        nr: 0,
        pn: 0,
    }
}

fn dh(private: &PrivateKey, public: &PublicKey) -> [u8; 32] {
    let shared = private
        .calculate_agreement(public)
        .expect("dh compute");
    let mut out = [0u8; 32];
    out.copy_from_slice(&shared);
    out
}

fn kdf_root(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut okm = [0u8; 64];
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_out);
    hk.expand(b"WhisperRatchet", &mut okm)
        .expect("kdf root");
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&okm[0..32]);
    chain_key.copy_from_slice(&okm[32..64]);
    (new_root, chain_key)
}

fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let new_chain_key = hmac_sha256(chain_key, &[0x02]);
    let message_key = hmac_sha256(chain_key, &[0x01]);
    (new_chain_key, message_key)
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac init");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn derive_message_keys(message_key: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let mut okm = [0u8; 80];
    let hk = Hkdf::<Sha256>::new(None, message_key);
    hk.expand(b"WhisperMessageKeys", &mut okm)
        .expect("message hkdf");
    let mut enc_key = [0u8; 32];
    let mut auth_key = [0u8; 32];
    let mut iv = [0u8; 16];
    enc_key.copy_from_slice(&okm[0..32]);
    auth_key.copy_from_slice(&okm[32..64]);
    iv.copy_from_slice(&okm[64..80]);
    (enc_key, auth_key, iv)
}

fn public_key_from_bytes(bytes: &[u8]) -> PublicKey {
    PublicKey::from_djb_public_key_bytes(bytes).expect("public key bytes")
}
