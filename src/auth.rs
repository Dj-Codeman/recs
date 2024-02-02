use hex;
use logging::append_log;
// use rand::distributions::{Distribution, Uniform};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::{
    fs::{read_to_string, OpenOptions},
    io::Write,
    str,
};
use system::{create_hash, del_file, errors::SystemError, is_path};

use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    config::USER_KEY_LOCATION,
    encrypt::{decrypt, encrypt},
    errors::{RecsError, RecsErrorType, RecsRecivedErrors},
    local_env::MAPS,
    local_env::VERSION,
    PROGNAME,
};

// pbkdf Generator specs
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_WRITTING_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

// ! ALL KEYS FOLLOW THIS STRUCT
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyIndex {
    pub hash: String,
    pub parent: String, // Default master or userkey
    pub location: String,
    pub version: String,
    pub key: u32,
}

// ! KEY GENERATION SECTION
pub fn generate_user_key(debug: bool) -> Result<(), RecsRecivedErrors> {
    // This function generates to key we use to encrypt data
    // The key is not actually stored but a value is encrypted with
    // A generated key and saved. At decryption time the key is checked against
    // The stored value. If it is the the same value are originally encrypted
    // We can attempt to decrypt the data given

    let salt: String = match fetch_chunk_helper(1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let secret: String = match fetch_chunk_helper(array_arimitics() - 1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidTypeGiven,
            )))
        }
    };
    let iteration = match std::num::NonZeroU32::new(num) {
        Some(d) => d,
        None => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidTypeGiven,
            )))
        }
    };
    let mut password_key = [0; 16]; // Setting the key size

    pbkdf2::derive(
        PBKDF2_ALG,
        iteration,
        salt.as_bytes(),
        secret.as_bytes(),
        &mut password_key,
    );

    let userkey = hex::encode(&password_key);
    // * creating the integrity file

    let secret: String = "The hotdog man isn't real !?".to_string();
    let cipher_integrity: String = match encrypt(secret.into(), userkey, 1024) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    // ! ^ this will use a static buffer size

    if is_path(&USER_KEY_LOCATION) {
        match debug {
            true => {
                del_file(&USER_KEY_LOCATION);
                append_log(unsafe { &PROGNAME }, "The old userkey has been deleted")
            }
            false => match del_file(&USER_KEY_LOCATION) {
                Ok(_) => Ok(()),
                Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
            },
        };
    }

    // creating the master.json file
    let mut userkey_file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&USER_KEY_LOCATION)
    {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorCreatingFile,
                &format!(
                    "An erro occoured while creating the master json file: {}",
                    e.to_string()
                ),
            )))
        }
    };

    match write!(userkey_file, "{}", cipher_integrity) {
        Ok(_) => match debug {
            true => append_log(
                unsafe { &PROGNAME },
                &format!(
                    "THIS IS A SECRET. The userkey check has been generated: {}",
                    &cipher_integrity
                ),
            ),
            false => Ok(()),
        },
        Err(e) => {
            append_log(
                unsafe { &PROGNAME },
                "An error occoured while writing data to the master json file",
            );
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorOpeningFile,
                &format!(
                    "Error couldn't write user key to the path specified: {}",
                    e.to_string()
                ),
            )));
        }
    };

    let checksum_string = create_hash(&cipher_integrity);

    // populated all the created data
    let userkey_map_data: KeyIndex = KeyIndex {
        hash: String::from(checksum_string),
        parent: String::from("SELF"),
        version: String::from(VERSION),
        location: String::from(USER_KEY_LOCATION),
        key: 0,
    };

    // formatting the json data
    let pretty_userkey_map = serde_json::to_string_pretty(&userkey_map_data).unwrap();

    // creating the json path
    let userkey_map_path = format!("{}/userkey.map", *MAPS);

    // Deleting and recreating the json file
    match del_file(&userkey_map_path) {
        Ok(_) => match debug {
            true => append_log(unsafe { &PROGNAME }, "Deleting old usrkey if it exists"),
            false => Ok(()),
        },
        Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
    };

    // writting to the master.json file
    let mut userkey_map_file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(userkey_map_path)
    {
        Ok(d) => d,
        Err(e) => {
            append_log(
                unsafe { &PROGNAME },
                &format!(
                    "Failed to open the new userkey.json path {}",
                    &userkey_map_path
                ),
            );
            return Err(RecsRecivedErrors::SystemError(SystemError::new(
                system::errors::SystemErrorType::ErrorOpeningFile,
            )));
        }
    };

    match writeln!(userkey_map_file, "{}", pretty_userkey_map) {
        Ok(d) => {
            append_log(unsafe { &PROGNAME }, "User authentication created");
            return Ok(());
        }
        Err(e) => {
            append_log(unsafe { &PROGNAME }, "Could save map data to file");
            return Err(RecsRecivedErrors::SystemError(SystemError::new(
                system::errors::SystemErrorType::ErrorOpeningFile,
            )));
        }
    };
}

pub fn auth_user_key() -> Result<String, RecsRecivedErrors> {
    append_log(
        unsafe { &PROGNAME },
        "user key authentication request started",
    );

    let salt: String = match fetch_chunk_helper(1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let secret: String = match fetch_chunk_helper(array_arimitics() - 1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidTypeGiven,
            )))
        }
    };
    let iteration = match std::num::NonZeroU32::new(num) {
        Some(d) => d,
        None => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidTypeGiven,
            )))
        }
    };
    let mut password_key = [0; 16]; // Setting the key size

    pbkdf2::derive(
        PBKDF2_ALG,
        iteration,
        salt.as_bytes(),
        secret.as_bytes(),
        &mut password_key,
    );

    let userkey = hex::encode(&password_key);
    let secret: String = "The hotdog man isn't real !?".to_string();
    // ! make the read the userkey from the map in the future
    let verification_ciphertext: String = match read_to_string(USER_KEY_LOCATION) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorReadingFile,
                &e.to_string(),
            )))
        }
    };

    let verification_result: String =
        match decrypt(&verification_ciphertext.to_string(), userkey.clone()) {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return Err(e),
        };

    match verification_result == secret {
        true => return Ok(userkey),
        false => {
            append_log(unsafe { &PROGNAME }, "Authentication request failed");
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidAuthRequest,
                &format!("Given: {} Expected: {}", &verification_result, &secret),
            )));
        }
    };
}

// todo change these security goals for multi system things

pub fn create_writing_key(key: String) -> Result<String, RecsRecivedErrors> {
    // golang compatible ????
    let mut prekey_str: String = String::new();
    prekey_str.push_str(&key);
    prekey_str.push_str(match auth_user_key() {
        Ok(d) => &d,
        Err(e) => return Err(e),
    });

    let prekey = create_hash(&prekey_str);

    let salt: String = match fetch_chunk_helper(1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidTypeGiven,
            )))
        }
    };
    let iteration = match std::num::NonZeroU32::new(num) {
        Some(d) => d,
        None => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidTypeGiven,
            )))
        }
    };
    let mut final_key = [0; 16];

    pbkdf2::derive(
        PBKDF2_WRITTING_ALG,
        iteration,
        salt.as_bytes(),
        prekey.as_bytes(),
        &mut final_key,
    );

    return Ok(hex::encode(final_key));
}

// * helper funtion for fetching chunks
fn fetch_chunk_helper(num: u32) -> Result<String, RecsRecivedErrors> {
    let chunk_data: String = match fetch_chunk(num) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };

    Ok(chunk_data)
}
