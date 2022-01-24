use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use sha2::{Sha256};
use sha2::Digest;
use std::fmt::Write;

fn main() {}

const ALICE: [u8; 32] = [0x18,0xa8,0x6a,0x6c,0x8a,0x38,0x18,0x28,
                         0x4b,0x5b,0x3a,0xb6,0x81,0xf9,0xce,0x15,
                         0x51,0x73,0xf5,0xb2,0x22,0x37,0x6d,0xd7,
                         0xa3,0x58,0xf4,0xf0,0x77,0x40,0x1b,0x59];

const BOB: [u8; 32]   = [0x19,0xa8,0x6a,0x6c,0x8a,0x38,0x18,0x28,
                         0x4b,0x5c,0x3a,0xb6,0x81,0xf9,0xce,0x15,
                         0x51,0x73,0xf5,0xb2,0x22,0x37,0x6d,0xd7,
                         0xa3,0x58,0xf4,0xf0,0x77,0x40,0x1b,0x59];

struct TxIn {
    outpoint: TxOut,
}

struct TxOut {
    value: u8,
    pubkey: [u8; 65]
}

struct Tx {
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>
}

impl Tx {
    fn serialize(&self) -> Vec<u8> {
        let mut sol = Vec::<u8>::new();
        for tx_in in &self.inputs {
            sol.push(tx_in.outpoint.value);
            sol.extend(tx_in.outpoint.pubkey);
        }
        for tx_out in &self.outputs {
            sol.push(tx_out.value);
            sol.extend(tx_out.pubkey);
        }
        sol
    }
}


fn get_hex_string(bytes: [u8; 32]) -> String {
    let mut s = String::with_capacity(2 * 32);
    for byte in bytes {
        write!(s, "{:02X}", byte);
    }
    s
}

#[test]
fn convert_bytes_to_hexstring() {
    let bytes: [u8; 32] = [0xb9,0x4d,0x27,0xb9,0x93,0x4d,0x3e,0x08,
                           0xa5,0x2e,0x52,0xd7,0xda,0x7d,0xab,0xfa,
                           0xc4,0x84,0xef,0xe3,0x7a,0x53,0x80,0xee,
                           0x90,0x88,0xf7,0xac,0xe2,0xef,0xcd,0xe9];
    let string = get_hex_string(bytes);
    assert!(string.to_lowercase() == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

#[test]
fn generate_keys_with_seed() {

    // openssl ecparam -genkey -name secp256k1 -out ec_key.pem -param_enc explicit
    // openssl ec -in ec_key.pem -noout -text

    let secret_key_slice = [0x18,0xa8,0x6a,0x6c,0x8a,0x38,0x18,0x28,
                            0x4b,0x5b,0x3a,0xb6,0x81,0xf9,0xce,0x15,
                            0x51,0x73,0xf5,0xb2,0x22,0x37,0x6d,0xd7,
                            0xa3,0x58,0xf4,0xf0,0x77,0x40,0x1b,0x59];

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&secret_key_slice).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let public_key_expected = [0x04,0x2d,0x08,0x69,0xa1,0x2f,0xa7,0x1b,
                               0x61,0xdc,0xd7,0xf4,0x1a,0x5d,0x92,0x6c,
                               0xf8,0x30,0xb4,0x7d,0xba,0x69,0xd8,0xd4,
                               0x8d,0xcc,0x57,0xf1,0x47,0x10,0x07,0x92,
                               0xdd,0x3f,0x47,0x95,0xc5,0x14,0x57,0x41,
                               0x4c,0xc0,0xe9,0x66,0x75,0xe0,0x51,0x40,
                               0x0c,0x1c,0x54,0x11,0xd0,0xe5,0x3e,0xb5,
                               0x79,0xfa,0xbe,0x9a,0x20,0x7f,0x07,0xcb,0xf5];

    assert!(public_key_expected == public_key.serialize_uncompressed());
}

#[test]
fn sign_and_verify_tx() {
    let secp = Secp256k1::new();
    let secret_key_alice = SecretKey::from_slice(&ALICE).expect("32 bytes, within curve order");
    let public_key_alice = PublicKey::from_secret_key(&secp, &secret_key_alice);

    let secret_key_bob = SecretKey::from_slice(&BOB).expect("32 bytes, within curve order");
    let public_key_bob = PublicKey::from_secret_key(&secp, &secret_key_bob);

    // This is for example and old UTXO transaction that Alice received 
    let tx_out_alice = TxOut {value: 50, pubkey: public_key_alice.serialize_uncompressed()};

    let tx_in = TxIn {outpoint: tx_out_alice};
    let tx_out_1 = TxOut {value: 20, pubkey: public_key_bob.serialize_uncompressed()};
    let tx_out_2 = TxOut {value: 30, pubkey: public_key_alice.serialize_uncompressed()};

    let tx = Tx {inputs: vec![tx_in], outputs: vec![tx_out_1, tx_out_2]};
    let tx_serial = tx.serialize();

    let mut hasher = Sha256::new();
    hasher.update(tx_serial);
    let hash = hasher.finalize();

    let message = Message::from_slice(&hash).expect("32 bytes");
    let sig = secp.sign_ecdsa(&message, &secret_key_alice);

    assert!(secp.verify_ecdsa(&message, &sig, &public_key_alice).is_ok());

    // Sign TX by Bob
    let message = Message::from_slice(&hash).expect("32 bytes");
    let sig = secp.sign_ecdsa(&message, &secret_key_bob);

    assert!(secp.verify_ecdsa(&message, &sig, &public_key_alice).is_err());
}