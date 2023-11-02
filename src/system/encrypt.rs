use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hex;
use hmac::{Hmac, Mac};
use pretty::{halt, notice};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use std::{process::exit, str};
use substring::Substring;
use system::truncate;

use crate::{array_tools::fetch_chunk, config::ARRAY_LEN};

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn create_secure_chunk() -> String {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(ARRAY_LEN as usize)
        .map(char::from)
        .collect();
    return key;
}

fn create_iv() -> String {
    // Generating initial vector
    let initial_vector: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    return initial_vector;
}

pub fn create_hash(data: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    return hex::encode(result);
    // 256 because its responsible for generating the writing keys
}

pub fn encrypt(data: String, key: String, buffer_size: usize) -> String {
    let iv = create_iv();
    let plain_text = data.as_bytes();
    let key = key.as_bytes();
    let cipher = Aes256Cbc::new_from_slices(&key, iv.as_bytes()).unwrap();
    let pad_len = plain_text.len();

    let mut buffer: Vec<u8> = vec![0; buffer_size * 8];
    // let mut buffer = [0u8; 256];

    buffer[..pad_len].copy_from_slice(plain_text);

    let ciphertext = hex::encode(cipher.encrypt(&mut buffer, pad_len).unwrap());

    let mut cipherdata = String::new();

    cipherdata.push_str(&ciphertext);
    cipherdata.push_str(&iv);

    // creating hmac
    let hmac = create_hmac(cipherdata.clone());

    cipherdata.push_str(&hmac);

    return cipherdata;
}

pub fn decrypt(cipherdata: String, key: String) -> String {
    let cipherdata = cipherdata.clone();
    //cipherdata legnth minus the hmac because its appened later
    let cipherdata_len: usize = cipherdata.len() - 64;

    // removed the hmac from the cipher string to generate the new hmac
    let cipherdata_hmacless: String = truncate(&cipherdata, cipherdata_len).to_string();

    // getting old and new hmac values
    let old_hmac = cipherdata.substring(cipherdata_len, cipherdata_len + 64);
    let new_hmac: String = create_hmac(cipherdata_hmacless.clone());

    // verifing hmac
    if old_hmac == new_hmac {
        // pulling the iv
        let initial_vector: &str = cipherdata.substring(cipherdata_len - 16, cipherdata_len);
        // define new cipher for decrypting
        let cipher = Aes256Cbc::new_from_slices(key.as_bytes(), initial_vector.as_bytes());
        // get the cipher text from the data bundle
        let encoded_ciphertext = truncate(&cipherdata, cipherdata_len - 16);
        // undo the hexencoding result
        let decoded_ciphertext = hex::decode(encoded_ciphertext).unwrap();
        // ! debugging 
        for value in &decoded_ciphertext {
            notice(&format!("{}", value))
        }
        // turn the data to a VEC byte array and decrypt it
        let mut buf = decoded_ciphertext.to_vec();
        // decrypt the binary data
        let decrypted_ciphertext = cipher
            .expect("Couldn't decrypt text")
            .decrypt(&mut buf)
            .unwrap();
        // turn it back into text
        return str::from_utf8(decrypted_ciphertext).unwrap().to_string();
    } else {
        // Breaking because the hmac isn't valid // ! add the right exit
        eprintln!("INVALID HMAC. TAMPERING DETECTED");
        exit(1);
    };
}

fn create_hmac(cipherdata: String) -> String {
    // create hmac
    type HmacSha256 = Hmac<Sha256>;

    // when the hmac is verified we check aginst the systemkey
    // * in the case of the chunk being illegible we do some screening
    let chunk_data: Option<String> = match fetch_chunk(1) {
        Some(data) => Some(data),
        None => None,
    };

    if chunk_data == None {
        halt(&format!("Failed to fetch chunk data for number 1"));
    };

    let mut mac =
        HmacSha256::new_from_slice(chunk_data.unwrap().as_bytes()).expect("An error occoured");

    mac.update(cipherdata.as_bytes());
    let hmac = truncate(&hex::encode(mac.finalize().into_bytes()), 64).to_string();

    if hmac.len() >= 65 {
        eprintln!("Invalid hmac generated");
    } else if hmac.len() <= 63 {
        eprintln!("HMAC TO SMALL");
    }

    return hmac;
}
