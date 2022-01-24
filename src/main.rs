use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use sha2::{Sha256};
use sha2::Digest;
use std::fmt::Write;
use hex_literal::hex;

fn main() {
    println!("Hello, world!");
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    println!("{:?}", secret_key);
    println!("{:?}", public_key);

    //let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());
    // This is unsafe unless the supplied byte slice is the output of a cryptographic hash function.
    // See the above example for how to use this library together with bitcoin_hashes.
    let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

    let sig = secp.sign_ecdsa(&message, &secret_key);
    assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());

    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(b"hello world");

    // read hash digest and consume hasher
    let result = hasher.finalize();
    println!("Hash = {:?}", result);

    let message = Message::from_slice(&result).expect("32 bytes");
    let sig = secp.sign_ecdsa(&message, &secret_key);

    let mut hasher = Sha256::new();
    hasher.update(b"Hello world");
    let result = hasher.finalize();
    let message = Message::from_slice(&result).expect("32 bytes");
    assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_err());

    let result_a: [u8; 32] = result.as_slice().try_into().expect("Wrong length");
    println!("{}", get_hex_string(result_a));

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