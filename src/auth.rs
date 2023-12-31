use pretty::halt;
use hex;
use logging::append_log;
// use rand::distributions::{Distribution, Uniform};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use system::{del_dir, is_path, del_file};
use std::{
    fs::{read_to_string, OpenOptions},
    io::Write,
    process::exit,
    str,
};

use crate::{
    config::USER_KEY_LOCATION,
    local_env::MAPS,
    encrypt::{create_hash, decrypt, encrypt}, local_env::{PROG, VERSION}, array_tools::fetch_chunk, array::array_arimitics,
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
pub fn generate_user_key() -> bool {
    // ! this is a key and a integrity check. the key is not stored but it is tested against a encrypted value

    let salt: String = fetch_chunk_helper(1);
    let secret: String = fetch_chunk_helper(array_arimitics() - 1);
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(num).unwrap();
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
    let cipher_integrity: String = encrypt(secret, userkey, 1024);
    // ! ^ this will be static since key sizes are really small

    if is_path(&USER_KEY_LOCATION){
        del_file(&USER_KEY_LOCATION);
    }

    // creating the master.json file
    let mut userkey_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&USER_KEY_LOCATION)
        .expect("File could not written to");

    if let Err(e) = write!(userkey_file, "{}", cipher_integrity) {
        let msg: String = format!("Error couldn't write user key to the path specified: {}", e.to_string());
        append_log(PROG,&msg);
        eprintln!("{}", &msg);
        return false;
    }

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
    del_dir(&userkey_map_path);

    // writting to the master.json file
    let mut userkey_map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(userkey_map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(userkey_map_file, "{}", pretty_userkey_map) {
        eprintln!("An error occoured");
        append_log(PROG,"Could save map data to file");
    }

    append_log(PROG,"User authentication created");
    return true;
}

pub fn auth_user_key() -> String {
    // ! patched to just used fixed key
    append_log(PROG,"user key authentication request started");

    let salt: String = fetch_chunk_helper(1);
    let secret: String = fetch_chunk_helper(array_arimitics() - 1);
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(num).unwrap();
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
    let verification_ciphertext: String =
        read_to_string(USER_KEY_LOCATION).expect("Couldn't read the map file");

    let verification_result: String =
        decrypt(verification_ciphertext.to_string(), userkey.clone());

    if verification_result == secret {
        return userkey;
    } else {
        append_log(PROG, "Authentication request failed");
        eprintln!("Auth error");
        exit(1);
    }
}


// todo change these security goals for multi system things

pub fn create_writing_key(key: String) -> String {
    // golang compatible ????
    let mut prekey_str: String = String::new();
    prekey_str.push_str(&key);
    prekey_str.push_str(&auth_user_key());

    let prekey = create_hash(&prekey_str);

    let salt: String = fetch_chunk_helper(1);
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(num).unwrap();
    let mut final_key = [0; 16];

    pbkdf2::derive(
        PBKDF2_WRITTING_ALG,
        iteration,
        salt.as_bytes(),
        prekey.as_bytes(),
        &mut final_key,
    );

    return hex::encode(final_key);
}

// * helper funtion for fetching chunks 
fn fetch_chunk_helper(num: u32) -> String {
    let chunk_data: Option<String> = match fetch_chunk(num) {
        Some(data) => Some(data),
        None => None,
    };

    if chunk_data == None {
        append_log(PROG, &format!("Error could not fetch the key: {}", num));
        halt(&format!("Failed to fetch chunk data for number 1"));
    };

    chunk_data.unwrap()
}
