use hex;

// use rand::distributions::{Distribution, Uniform};
use dusa_collection_utils::{
    errors::{ErrorArrayItem, Errors, UnifiedResult as uf}, functions::{create_hash, path_present}, log, logger::LogLevel, types::{pathtype::PathType, stringy::Stringy}
};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::{
    fs::{read_to_string, OpenOptions},
    io::Write,
    str,
};

use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    encrypt::{decrypt, encrypt},
    local_env::{SystemPaths, VERSION},
};

// pbkdf Generator specs
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_WRITING_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

// ! ALL KEYS FOLLOW THIS STRUCT
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyIndex {
    pub hash: Stringy,
    pub parent: Stringy, // Default master or userkey
    pub location: Stringy,
    pub version: Stringy,
    pub key: u32,
}

// ! KEY GENERATION SECTION
pub async fn generate_user_key(debug: bool) -> uf<()> {
    // This function generates to key we use to encrypt data
    // The key is not actually stored but a value is encrypted with
    // A generated key and saved. At decryption time the key is checked against
    // The stored value. If it is the the same value are originally encrypted
    // We can attempt to decrypt the data given

    let salt: String = match fetch_chunk_helper(1).await.uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };
    let secret: String = match fetch_chunk_helper(array_arimitics() - 1).await.uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };
    let iteration = match std::num::NonZeroU32::new(num) {
        Some(d) => d,
        None => {
            return uf::new(Err(ErrorArrayItem::new(
                Errors::InvalidType,
                String::from("string conversion error"),
            )));
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
    let cipher_integrity: String = match encrypt(secret.into(), userkey.into(), 1024).uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };

    let system_paths: SystemPaths = SystemPaths::read_current().await;

    match path_present(&system_paths.USER_KEY_LOCATION).uf_unwrap() {
        Ok(true) => {

            match system_paths.USER_KEY_LOCATION.delete() {
                Ok(_) => {
                    if debug {
                        log!(LogLevel::Trace, "The old userkey has been deleted");
                    }
                }
                Err(e) => return uf::new(Err(e)),
            }
        }
        Ok(false) => (),
        Err(e) => return uf::new(Err(e)),
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
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };

    if let Err(e) = write!(userkey_file, "{}", cipher_integrity) {
        log!(
            LogLevel::Error,
            "An error occurred while writing data to the master JSON file"
        );
        return uf::new(Err(ErrorArrayItem::from(e)));
    }

    if debug {
        log!(
            LogLevel::Trace,
            "THIS IS A SECRET. The userkey check has been generated: {}",
            &cipher_integrity
        );
    }

    let checksum_string = create_hash(cipher_integrity);

    // populated all the created data
    let userkey_map_data: KeyIndex = KeyIndex {
        hash: checksum_string,
        parent: Stringy::from("SELF"),
        version: Stringy::from(VERSION),
        location: (&system_paths.USER_KEY_LOCATION).to_string().into(),
        key: 0,
    };

    // formatting the json data
    let pretty_userkey_map: String = serde_json::to_string_pretty(&userkey_map_data).unwrap();

    // creating the json path
    let userkey_map_path: PathType =
        PathType::Content(format!("{}/userkey.map", system_paths.MAPS));

    // Deleting and recreating the json file
    if let Err(e) = userkey_map_path.delete() {
        return uf::new(Err(e));
    }

    // writing to the master.json file
    let mut userkey_map_file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&userkey_map_path)
    {
        Ok(d) => d,
        Err(e) => {
            log!(
                LogLevel::Error,
                "Failed to open the new userkey.json path {}, {}",
                &userkey_map_path,
                e
            );
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };

    match writeln!(userkey_map_file, "{}", pretty_userkey_map) {
        Ok(_) => {
            log!(LogLevel::Debug, "User authentication created");
            return uf::new(Ok(()));
        }
        Err(e) => {
            log!(LogLevel::Error, "Could save map data to file: {}", e);
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };
}

pub async fn auth_user_key() -> uf<String> {
    let system_paths: SystemPaths = SystemPaths::read_current().await;
    // let _ = append_log(
    //     unsafe { &PROGNAME },
    //     "user key authentication request started",
    // );

    let salt: String = match fetch_chunk_helper(1).await.uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };
    let secret: String = match fetch_chunk_helper(array_arimitics() - 1).await.uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };
    let iteration = match std::num::NonZeroU32::new(num) {
        Some(d) => d,
        None => {
            return uf::new(Err(ErrorArrayItem::new(
                Errors::InvalidType,
                String::from("string conversion error"),
            )));
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
    let verification_ciphertext: Stringy = match read_to_string(&system_paths.USER_KEY_LOCATION) {
        Ok(d) => Stringy::from(d),
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };

    let verification_result: String =
        match decrypt(verification_ciphertext, &userkey).uf_unwrap() {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return uf::new(Err(e)),
        };

    match verification_result == secret {
        true => return uf::new(Ok(userkey)),
        false => {
            log!(LogLevel::Error, "Authentication request failed");
            return uf::new(Err(ErrorArrayItem::new(
                Errors::InvalidSignature,
                format!("Given: {} Expected: {}", &verification_result, &secret),
            )));
        }
    };
}

// todo change these security goals for multi system things

pub async fn create_writing_key(key: String, fixed_key: bool) -> uf<String> {
    // golang compatible ????
    let mut prekey_str: String = String::new();

    let user_key: String = match fixed_key {
        true => key.clone(),
        false => match auth_user_key().await.uf_unwrap() {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        },
    };

    prekey_str.push_str(&key);
    prekey_str.push_str(&user_key);

    let prekey = create_hash(prekey_str);

    let salt: String = match fetch_chunk_helper(1).await.uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };
    let num: u32 = match "95180".parse() {
        Ok(d) => d,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };
    let iteration = match std::num::NonZeroU32::new(num) {
        Some(d) => d,
        None => {
            return uf::new(Err(ErrorArrayItem::new(
                Errors::InvalidType,
                String::from("string conversion error"),
            )));
        }
    };
    let mut final_key = [0; 16];

    pbkdf2::derive(
        PBKDF2_WRITING_ALG,
        iteration,
        salt.as_bytes(),
        prekey.as_bytes(),
        &mut final_key,
    );

    return uf::new(Ok(hex::encode(final_key)));
}

// * helper function for fetching chunks
async fn fetch_chunk_helper(num: u32) -> uf<String> {
    let chunk_data: String = match fetch_chunk(num).await.uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };

    uf::new(Ok(chunk_data))
}
