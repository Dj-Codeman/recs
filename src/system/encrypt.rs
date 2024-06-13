use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hex::encode;
use hmac::{Hmac, Mac};
use logging::append_log;
use pretty::warn;
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use std::str;
use substring::Substring;
use system::{
    errors::{ErrorArray, ErrorArrayItem, Errors as SE, UnifiedResult as uf},
    functions::truncate,
};

use crate::{
    // array_tools::fetch_chunk,
    config::ARRAY_LEN,
    PROGNAME,
};

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

pub fn encrypt(
    data: Vec<u8>,
    key: Vec<u8>,
    buffer_size: usize,
    mut errors: ErrorArray,
) -> uf<String> {
    let iv = create_iv();
    let key: Vec<u8> = match key.try_into() {
        Ok(d) => d,
        Err(_) => {
            errors.push(ErrorArrayItem::new(
                SE::InvalidKey,
                format!("Invalid key length"),
            ));
            return uf::new(Err(errors));
        }
    };

    let cipher: Cbc<Aes256, Pkcs7> = match Aes256Cbc::new_from_slices(&key, iv.as_bytes()) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::new(SE::InvalidKey, e.to_string()));
            return uf::new(Err(errors));
        }
    };

    let pad_len: usize = data.len();
    let mut buffer: Vec<u8> = if pad_len > buffer_size {
        vec![0; buffer_size + pad_len * 2]
    } else {
        vec![0; buffer_size + pad_len]
    };

    buffer[..pad_len].copy_from_slice(&data);

    let ciphertext: String = encode(match cipher.encrypt(&mut buffer, pad_len) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::new(SE::InvalidBlockData, e.to_string()));
            return uf::new(Err(errors));
        }
    });

    let mut cipherdata = String::new();

    cipherdata.push_str(&ciphertext);
    cipherdata.push_str(&iv);

    // Simplefies the function call for creating the hmac
    let safe_derive_key: String = match String::from_utf8(key) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::new(SE::InvalidUtf8Data, e.to_string()));
            return uf::new(Err(errors));
        }
    };

    // creating hmac
    let hmac = match create_hmac(&cipherdata, &safe_derive_key, errors.clone()).uf_unwrap() {
        Ok(d) => {
            println!("Generated hmac {}", d);
            d
        },
        Err(e) => return uf::new(Err(e)),
    };

    cipherdata.push_str(&hmac);

    if cipherdata.len() == 0 {
        let _ = append_log(
            unsafe { PROGNAME },
            "NO CIPHER DATA RECIVED",
            errors.clone(),
        );
        errors.push(ErrorArrayItem::new(
            SE::GeneralError,
            format!("Cipher data length is 0"),
        ));
        return uf::new(Err(errors));
    }

    uf::new(Ok(cipherdata))
}

pub fn decrypt(cipherdata: &str, key: &str, mut errors: ErrorArray) -> uf<Vec<u8>> {
    // * Changing this to run on refrenced data to hopefully run with a smaller ram footprint
    //cipherdata legnth minus the hmac because its appened later
    let cipherdata_len: usize = cipherdata.len() - 62;

    // removed the hmac from the cipher string to generate the new hmac
    let cipherdata_hmacless: &str = truncate(&cipherdata, cipherdata_len);

    // getting old and new hmac values
    let old_hmac: String = cipherdata
        .substring(cipherdata_len, cipherdata_len + 64)
        .to_owned();
    let new_hmac: String = match create_hmac(cipherdata_hmacless, key, errors.clone()).uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };


    // verifing hmac
    match old_hmac == new_hmac {
        true => {
            // pulling the iv
            let initial_vector: &str = cipherdata.substring(cipherdata_len - 16, cipherdata_len);
            // define new cipher for decrypting
            let cipher = Aes256Cbc::new_from_slices(key.as_bytes(), initial_vector.as_bytes());
            // get the cipher text from the data bundle
            let encoded_ciphertext: &str = truncate(&cipherdata, cipherdata_len - 16);
            // undo the hexencoding result
            let decoded_ciphertext: Vec<u8> = match hex::decode(encoded_ciphertext) {
                Ok(d) => d,
                Err(e) => {
                    errors.push(ErrorArrayItem::new(SE::InvalidHexData, e.to_string()));
                    return uf::new(Err(errors));
                }
            };
            // turn the data to a VEC byte array and decrypt it
            let mut buf = decoded_ciphertext.to_vec();
            // decrypt the binary data
            let decrypted_bytes = match cipher {
                Ok(d) => match d.decrypt(&mut buf) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::new(SE::InvalidBlockData, e.to_string()));
                        return uf::new(Err(errors));
                    }
                },
                Err(e) => {
                    errors.push(ErrorArrayItem::new(SE::InvalidKey, e.to_string()));
                    return uf::new(Err(errors));
                }
            };
            // turn it back into text
            return uf::new(Ok(decrypted_bytes.to_vec()));
        }
        false => {
            errors.push(ErrorArrayItem::new(SE::InvalidHMACData, "".to_string()));
            return uf::new(Err(errors));
        }
    }
}

fn create_hmac(cipherdata: &str, derive_key: &str, mut errors: ErrorArray) -> uf<String> {
    // create hmac
    type HmacSha256 = Hmac<Sha256>;

    // when the hmac is verified we check aginst the systemkey
    // * in the case of the chunk being illegible we do some screening
    let chunk_data: String = derive_key.to_owned();
    // let chunk_data: String = match fetch_chunk(1) {
    //     Ok(d) => d,
    //     Err(e) => return Err(e),
    // };

    let mut mac = match HmacSha256::new_from_slice(chunk_data.as_bytes()) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::new(SE::InvalidHMACSize, e.to_string()));
            return uf::new(Err(errors));
        }
    };

    mac.update(cipherdata.as_bytes());
    let hmac = truncate(&hex::encode(mac.finalize().into_bytes()), 64).to_owned();
    match hmac.len() == 64 {
        true => return uf::new(Ok(hmac)),
        false => {
            warn(&format!("Invalid hmac size: {}", hmac));
            errors.push(ErrorArrayItem::new(SE::InvalidHMACSize, "".to_string()));
            return uf::new(Err(errors));
        }
    };
}
