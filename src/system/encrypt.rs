use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hex::{self, encode};
use hmac::{Hmac, Mac};
use logging::append_log;
use pretty::{dump, output, warn};
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use std::str;
use substring::Substring;
use system::truncate;

use crate::{
    array_tools::fetch_chunk,
    config::ARRAY_LEN,
    errors::{RecsError, RecsErrorType, RecsRecivedErrors},
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
) -> Result<String, RecsRecivedErrors> {
    let iv = create_iv();
    let key: Vec<u8> = key.try_into().map_err(|_| {
        RecsRecivedErrors::RecsError(RecsError::new_details(
            RecsErrorType::InvalidKey,
            "Invalid key length",
        ))
    })?;

    let cipher = Aes256Cbc::new_from_slices(&key, iv.as_bytes()).map_err(|e| {
        RecsRecivedErrors::RecsError(RecsError::new_details(RecsErrorType::Error, &e.to_string()))
    })?;

    let pad_len = data.len();
    let mut buffer: Vec<u8> = if pad_len > buffer_size {
        vec![0; buffer_size + pad_len * 2]
    } else {
        vec![0; buffer_size + pad_len]
    };

    buffer[..pad_len].copy_from_slice(&data);

    let ciphertext = encode(match cipher.encrypt(&mut buffer, pad_len) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidBlockData,
                &e.to_string(),
            )))
        }
    });

    let mut cipherdata = String::new();

    cipherdata.push_str(&ciphertext);
    cipherdata.push_str(&iv);

    // creating hmac
    let hmac = create_hmac(&cipherdata)?;
    warn(&hmac);

    cipherdata.push_str(&hmac);

    if cipherdata.len() == 0 {
        let _ = append_log(unsafe { PROGNAME }, "NO CIPHER DATA RECIVED");
        return Err(RecsRecivedErrors::RecsError(RecsError::new(
            RecsErrorType::Error,
        )));
    }

    Ok(cipherdata)
}

pub fn decrypt(cipherdata: &str, key: &str) -> Result<Vec<u8>, RecsRecivedErrors> {
    // * Changing this to run on refrenced data to hopefully run with a smaller ram footprint
    //cipherdata legnth minus the hmac because its appened later
    let cipherdata_len: usize = cipherdata.len() - 64;

    // removed the hmac from the cipher string to generate the new hmac
    let cipherdata_hmacless: &str = truncate(&cipherdata, cipherdata_len);
    warn(&format!("Data without hmac {}", cipherdata_hmacless));

    // getting old and new hmac values
    let old_hmac: String = cipherdata.substring(cipherdata_len, cipherdata_len + 64).to_owned();
    let new_hmac: String = match create_hmac(cipherdata_hmacless) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    warn(&format!("The hmac on file {}", &old_hmac));
    warn(&format!("New hmac {}", &new_hmac));

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
                    return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                        RecsErrorType::InvalidHexData,
                        &e.to_string(),
                    )))
                }
            };
            // turn the data to a VEC byte array and decrypt it
            let mut buf = decoded_ciphertext.to_vec();
            // decrypt the binary data
            let decrypted_bytes = match cipher {
                Ok(d) => match d.decrypt(&mut buf) {
                    Ok(d) => d,
                    Err(e) => {
                        return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                            RecsErrorType::InvalidBlockData,
                            &e.to_string(),
                        )))
                    }
                },
                Err(e) => {
                    return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                        RecsErrorType::InvalidIvData,
                        &e.to_string(),
                    )))
                }
            };
            // turn it back into text
            return Ok(decrypted_bytes.to_vec());
        }
        false => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidHMACData,
            )))
        }
    }
}

fn create_hmac(cipherdata: &str) -> Result<String, RecsRecivedErrors> {
    // create hmac
    type HmacSha256 = Hmac<Sha256>;

    // when the hmac is verified we check aginst the systemkey
    // * in the case of the chunk being illegible we do some screening
    let chunk_data: String = match fetch_chunk(1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };

    let mut mac = match HmacSha256::new_from_slice(chunk_data.as_bytes()) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidHMACSize,
                &e.to_string(),
            )))
        }
    };

    mac.update(cipherdata.as_bytes());
    let hmac = truncate(&hex::encode(mac.finalize().into_bytes()), 64).to_owned();
    match hmac.len() == 64 {
        true => return Ok(hmac),
        false => {
            dump(&hmac);
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidHMACSize,
            )))
        }
    };
}
