use hex;
use logging::append_log;
use pretty::notice;
// use rand::distributions::{Distribution, Uniform};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::{
    fs::{read_to_string, OpenOptions},
    io::Write,
    str,
};
use system::{create_hash, del_file, errors::SystemError, path_present, ClonePath, PathType};

use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    encrypt::{decrypt, encrypt},
    errors::{RecsError, RecsErrorType, RecsRecivedErrors},
    local_env::{SystemPaths, VERSION},
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
        Err(_) => {
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
    let cipher_integrity: String = match encrypt(secret.into(), userkey.into(), 1024) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };

    let system_paths: SystemPaths = SystemPaths::new();

    match path_present(&system_paths.USER_KEY_LOCATION) {
        Ok(d) => match d {
            true => match debug {
                true => {
                    match del_file(system_paths.USER_KEY_LOCATION.clone_path()) {
                        Ok(_) => {
                            notice(&format!("{}: deleted", system_paths.USER_KEY_LOCATION.to_string()));
                            let _ = append_log(unsafe { &PROGNAME }, "The old userkey has been deleted");
                        }
                        Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
                    };
                }
                false => {
                    match del_file(system_paths.USER_KEY_LOCATION.clone_path()) {
                        Ok(_) => (),
                        Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
                    };
                }
            },
            false => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorDeletingFile,
                    &system_paths.USER_KEY_LOCATION.to_string(),
                )))
            }
        },
        Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
    }

    // creating the master.json file
    let mut userkey_file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&system_paths.USER_KEY_LOCATION)
    {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorCreatingFile,
                &format!(
                    "An error occoured while creating the master json file: {}",
                    e.to_string()
                ),
            )))
        }
    };

    let _ = match write!(userkey_file, "{}", cipher_integrity) {
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
            let _ = append_log(
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

    let checksum_string = create_hash(cipher_integrity);

    // populated all the created data
    let userkey_map_data: KeyIndex = KeyIndex {
        hash: String::from(checksum_string),
        parent: String::from("SELF"),
        version: String::from(VERSION),
        location: (&system_paths.USER_KEY_LOCATION).to_string(),
        key: 0,
    };

    // formatting the json data
    let pretty_userkey_map: String = serde_json::to_string_pretty(&userkey_map_data).unwrap();

    // creating the json path
    let userkey_map_path: PathType = PathType::Content(format!("{}/userkey.map", system_paths.MAPS));

    // Deleting and recreating the json file
    let _ = match del_file(userkey_map_path.clone_path()) {
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
        .open(&userkey_map_path)
    {
        Ok(d) => d,
        Err(e) => {
            let _ = append_log(
                unsafe { &PROGNAME },
                &format!(
                    "Failed to open the new userkey.json path {}, {}",
                    &userkey_map_path, e
                ),
            );
            return Err(RecsRecivedErrors::SystemError(SystemError::new(
                system::errors::SystemErrorType::ErrorOpeningFile,
            )));
        }
    };

    match writeln!(userkey_map_file, "{}", pretty_userkey_map) {
        Ok(_) => {
            let _ = append_log(unsafe { &PROGNAME }, "User authentication created");
            return Ok(());
        }
        Err(e) => {
            let _ = append_log(
                unsafe { &PROGNAME },
                &format!("Could save map data to file: {}", e),
            );
            return Err(RecsRecivedErrors::SystemError(SystemError::new(
                system::errors::SystemErrorType::ErrorOpeningFile,
            )));
        }
    };
}

pub fn auth_user_key() -> Result<String, RecsRecivedErrors> {
    let system_paths: SystemPaths = SystemPaths::new();
    let _ = append_log(
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
        Err(_) => {
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
    let verification_ciphertext: String = match read_to_string(&system_paths.USER_KEY_LOCATION) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorReadingFile,
                &e.to_string(),
            )))
        }
    };

    let verification_result: String = match decrypt(&verification_ciphertext.to_string(), &userkey)
    {
        Ok(d) => String::from_utf8_lossy(&d).to_string(),
        Err(e) => return Err(e),
    };

    match verification_result == secret {
        true => return Ok(userkey),
        false => {
            match append_log(unsafe { &PROGNAME }, "Authentication request failed") {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::repack(e)),
            };
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidAuthRequest,
                &format!("Given: {} Expected: {}", &verification_result, &secret),
            )));
        }
    };
}

// todo change these security goals for multi system things

pub fn create_writing_key(key: String, fixed_key: bool) -> Result<String, RecsRecivedErrors> {
    // golang compatible ????
    let mut prekey_str: String = String::new();

    let user_key: String = match fixed_key {
        true => key.clone(),
        false => match auth_user_key() {
            Ok(d) => d,
            Err(e) => return Err(e),
        },
    };

    prekey_str.push_str(&key);
    prekey_str.push_str(&user_key);

    let prekey = create_hash(prekey_str);

    let salt: String = match fetch_chunk_helper(1) {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(_) => {
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
