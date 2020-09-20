extern crate wasm_bindgen;

// mod utils;

use aes::block_cipher::generic_array::GenericArray;
use aes::block_cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;
use rand::prelude::*;
use rand::SeedableRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use wasm_bindgen::prelude::*;

mod utils;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn time(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn timeEnd(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn rsa_encrypt(data: &str, pub_key: &str) -> String {
    // let mut rng = OsRng;
    let seed_array: [u8; 32] = [0; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed_array);
    // let bits = 2048;
    // let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // let public_key = RSAPublicKey::from(&private_key);
    let der_encoded = pub_key.lines().filter(|line| !line.starts_with("-")).fold(
        String::new(),
        |mut data, line| {
            data.push_str(&line);
            data
        },
    );
    let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");
    let public_key = RSAPublicKey::from_pkcs8(&der_bytes).expect("failed to parse a pub key");

    // Encrypt
    // let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data.as_bytes())
        .expect("failed to encrypt");

    return base64::encode(enc_data);
    // assert_ne!(&data[..], &enc_data[..]);
}

#[wasm_bindgen]
pub fn rsa_decrypt(enc_data: &str, pri_key: &str) -> String {
    // let mut rng = OsRng;
    // let seed_array: [u8; 32] = [0; 32];
    // let mut rng: StdRng = SeedableRng::from_seed(seed_array);
    // let bits = 2048;
    // let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // let public_key = RSAPublicKey::from(&private_key);

    let der_encoded = pri_key.lines().filter(|line| !line.starts_with("-")).fold(
        String::new(),
        |mut data, line| {
            data.push_str(&line);
            data
        },
    );

    let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");
    let private_key = RSAPrivateKey::from_pkcs8(&der_bytes).expect("failed to parse a pri key");
    let enc_bytes = base64::decode(&enc_data).expect("failed to parse a pri key");

    // Decrypt
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_bytes)
        .expect("failed to decrypt");

    return String::from_utf8(dec_data).expect("failed to decrypt");
    // assert_eq!(&data[..], &dec_data[..]);
}

#[wasm_bindgen]
pub fn test_aes() {
    let key = GenericArray::from_slice(&[0u8; 16]);
    let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
    let mut block8 = GenericArray::clone_from_slice(&[block; 8]);
    // Initialize cipher
    let cipher = Aes128::new(&key);

    let block_copy = block.clone();
    // Encrypt block in-place
    cipher.encrypt_block(&mut block);
    // And decrypt it back
    cipher.decrypt_block(&mut block);
    assert_eq!(block, block_copy);

    // We can encrypt 8 blocks simultaneously using
    // instruction-level parallelism
    let block8_copy = block8.clone();
    cipher.encrypt_blocks(&mut block8);
    cipher.decrypt_blocks(&mut block8);
    assert_eq!(block8, block8_copy);
}

#[wasm_bindgen]
pub fn greet() {
    // time("[RUST EAS TASK]");
    // test_aes();
    // timeEnd("[RUST EAS TASK]");
}
