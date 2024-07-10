use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hex::{self, encode};
use hmac::{Hmac, Mac};
use pretty::{dump, warn};
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use std::str;
use substring::Substring;
use system::{
    errors::{ErrorArray, ErrorArrayItem, Errors, UnifiedResult as uf},
    functions::truncate,
};

use crate::{
    // array_tools::fetch_chunk,
    config::ARRAY_LEN, log::log,
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
    let key_result: Result<Vec<u8>, ErrorArrayItem> =
        key.try_into().map_err(|e| ErrorArrayItem::from(e));

    let key = match key_result {
        Ok(d) => d,
        Err(e) => {
            errors.push(e);
            return uf::new(Err(errors));
        }
    };

    let cipher_result =
        Aes256Cbc::new_from_slices(&key, iv.as_bytes()).map_err(|e| ErrorArrayItem::from(e));

    let cipher = match cipher_result {
        Ok(d) => d,
        Err(e) => {
            errors.push(e);
            return uf::new(Err(errors));
        }
    };

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
            let err_item = ErrorArrayItem::from(e);
            errors.push(err_item);
            return uf::new(Err(errors));
        }
    });

    let mut cipherdata = String::new();

    cipherdata.push_str(&ciphertext);
    cipherdata.push_str(&iv);

    // creating hmac
    let key_str = String::from_utf8(key).map_err(|e| ErrorArrayItem::from(e));

    let hmac = match key_str {
        Ok(key) => match create_hmac(&cipherdata, &key) {
            Ok(d) => d,
            Err(e) => {
                errors.push(e);
                return uf::new(Err(errors));
            }
        },
        Err(e) => {
            errors.push(e);
            return uf::new(Err(errors));
        }
    };

    cipherdata.push_str(&hmac);

    if cipherdata.is_empty() {
    log("No cipher data recived".to_string());

        errors.push(ErrorArrayItem::new(
            Errors::GeneralError,
            "No cipher data received".to_string(),
        ));
    }

    uf::new(Ok(cipherdata))
}

pub fn decrypt(cipherdata: &str, key: &str, mut errors: ErrorArray) -> uf<Vec<u8>> {
    // Calculate the length of cipherdata minus the HMAC
    let cipherdata_len: usize = cipherdata.len() - 64;

    // Remove the HMAC from the cipherdata
    let cipherdata_hmacless: &str = truncate(&cipherdata, cipherdata_len);

    // Get old and new HMAC values
    let old_hmac: String = cipherdata
        .substring(cipherdata_len, cipherdata_len + 64)
        .to_owned();

    let new_hmac: String = match create_hmac(cipherdata_hmacless, key) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    warn(&old_hmac);
    warn(&new_hmac);
    warn(&cipherdata_hmacless);

    // Verify HMAC
    if old_hmac != new_hmac {
        errors.push(ErrorArrayItem::new(
            Errors::InvalidHMACData,
            "Invalid HMAC".to_string(),
        ));
        return uf::new(Err(errors));
    }

    // Extract IV
    let initial_vector: &str = cipherdata.substring(cipherdata_len - 16, cipherdata_len);

    // Define cipher for decryption
    let cipher_result: Result<Cbc<Aes256, Pkcs7>, ErrorArrayItem> =
        Aes256Cbc::new_from_slices(key.as_bytes(), initial_vector.as_bytes())
            .map_err(|e| ErrorArrayItem::from(e));

    // Extract ciphertext and decode from hex
    let encoded_ciphertext: &str = truncate(&cipherdata, cipherdata_len - 16);

    let decoded_ciphertext_result: Result<Vec<u8>, ErrorArrayItem> =
        hex::decode(encoded_ciphertext)
            .map_err(|e| ErrorArrayItem::new(Errors::InvalidHexData, e.to_string()));

    // Decrypt the data
    let mut buf: Vec<u8> = match decoded_ciphertext_result {
        Ok(d) => d,
        Err(e) => {
            errors.push(e);
            return uf::new(Err(errors));
        }
    };

    let decrypted_bytes_result: Result<Vec<u8>, block_modes::BlockModeError> = match cipher_result {
        Ok(cipher) => cipher.decrypt(&mut buf).map(|b| b.to_vec()),
        Err(e) => {
            errors.push(e);
            return uf::new(Err(errors));
        }
    };

    match decrypted_bytes_result {
        Ok(d) => uf::new(Ok(d)),
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            uf::new(Err(errors))
        }
    }
}

fn create_hmac(cipherdata: &str, derive_key: &str) -> Result<String, ErrorArrayItem> {
    type HmacSha256 = Hmac<Sha256>;

    // When the HMAC is verified we check against the system key
    let chunk_data: String = derive_key.to_owned();

    // Create a new HMAC instance
    let mut mac = HmacSha256::new_from_slice(chunk_data.as_bytes())
        .map_err(|e| ErrorArrayItem::new(Errors::InvalidHMACSize, e.to_string()))?;

    // Update the HMAC with the cipher data
    mac.update(cipherdata.as_bytes());

    // Generate the HMAC and truncate it to 64 characters
    let hmac = truncate(&hex::encode(mac.finalize().into_bytes()), 64).to_owned();

    // Check if the length of the HMAC is correct
    if hmac.len() == 64 {
        Ok(hmac)
    } else {
        dump(&hmac);
        Err(ErrorArrayItem::new(
            Errors::InvalidHMACSize,
            "HMAC size is invalid".to_string(),
        ))
    }
}
