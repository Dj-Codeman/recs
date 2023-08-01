use hex;
use rand::distributions::{Distribution, Uniform};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions, read_to_string},
    io::{prelude::*, SeekFrom, Write},
    str,
};

use crate::{
    config::{
        ARRAY_LEN, PRE_DEFINED_USERKEY, PUBLIC_MAP_DIRECTORY, SYSTEM_ARRAY_LOCATION,
        USER_KEY_LOCATION, USE_PRE_DEFINED_USERKEY,
    },
    encrypt::{create_hash, create_secure_chunk, decrypt, encrypt},
    system::{append_log, halt, notice, unexist, warn, VERSION, output},
};

// pbkdf Generator specs
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_WRITTING_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

// system array definitions
// make this more dynamic or sum like that

const BEG_CHAR: u32 = 40;
const END_CHAR: u32 = 80984; //80,999
const CHUNK_SIZE: usize = 16; //5060

// ! ALL KEYS FOLLOW THIS STRUCT
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyIndex {
    pub hash: String,
    pub parent: String, // Default master or userkey
    pub location: String,
    pub version: String,
    pub key: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChunkMap {
    pub location: String,
    pub version: String,
    pub chunk_num: u32,
    pub chunk_hsh: String,
    pub chunk_beg: u32,
    pub chunk_end: u32,
}

// ! KEY GENERATION SECTION
pub fn generate_user_key() -> bool {
    // ! this is a key and a integrity check. the key is not stored but it is tested against a encrypted value

    let salt: String = fetch_chunk(1);
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(num).unwrap();
    let mut password_key = [0; 16]; // Setting the key size

    if USE_PRE_DEFINED_USERKEY {
        pbkdf2::derive(
            PBKDF2_ALG,
            iteration,
            salt.as_bytes(),
            PRE_DEFINED_USERKEY.as_bytes(),
            &mut password_key,
        );
    }

    let userkey = hex::encode(&password_key);
    // * creating the integrity file

    let secret: String = "The hotdog man isn't real !?".to_string();
    let cipher_integrity: String = encrypt(secret, userkey, 1024);
    // ! ^ this will be static since key sizes are really small

    unexist(&USER_KEY_LOCATION);

    // creating the master.json file
    let mut userkey_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&USER_KEY_LOCATION)
        .expect("File could not written to");

    if let Err(e) = write!(userkey_file, "{}", cipher_integrity) {
        let mut msg: String = String::new();
        msg.push_str("Error couldn't write user key to the path specified:: '");
        msg.push_str(&String::from(e.to_string()));
        msg.push_str("'");
        append_log(&msg);
        halt(&msg);
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
    let mut userkey_map_path: String = String::new();
    userkey_map_path.push_str(PUBLIC_MAP_DIRECTORY);
    userkey_map_path.push_str("/userkey.json");

    // Deleting and recreating the json file
    unexist(&userkey_map_path);

    // writting to the master.json file
    let mut userkey_map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(userkey_map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(userkey_map_file, "{}", pretty_userkey_map) {
        halt("Could not write json data to file");
    }

    notice("User authentication created");
    return true;
}

pub fn generate_system_array() -> bool {
    append_log("Creating system array");

    // writing the system key to the file specified
    unexist(&SYSTEM_ARRAY_LOCATION);

    // Creating the key file
    // ! Creating Header
    // ? ie <--RECS System Array Version RX.X.X-->\n
    // ? Rust Encryption Core System RECS
    // ? HEADER CHARSIZE 39
    let mut system_array_header: String = String::new();
    system_array_header.push_str("<--REcS System Array Version ");
    system_array_header.push_str(VERSION);
    system_array_header.push_str("-->\n"); //40

    // ! Creating Body
    // ? Total possible keys 5060
    let system_array_chunk: String = create_secure_chunk(); //81,000

    // ! Creating Footer
    let mut system_array_footer: String = String::new();
    system_array_footer.push_str("\n</--REcS System Array-->"); //81,025

    // ! Assembeling array
    let mut system_array: String = String::new();
    system_array.push_str(&system_array_header);
    system_array.push_str(&system_array_chunk);
    system_array.push_str(&system_array_footer);

    // opening the file to write data to it
    let mut system_array_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(SYSTEM_ARRAY_LOCATION)
        .expect("File could not be opened");

    // writing the data and checking for errors
    if let Err(_e) = write!(system_array_file, "{}", system_array) {
        warn("Could not write the system_array to the path specified");
        return false;
    }

    notice("Created system array");
    return true;
}

pub fn index_system_array() -> bool {
    // ? Defining initial chunks parameters
    let mut chunk_number: u32 = 1;

    // ? Defing read heads and initial reading ranges
    let mut range_start: u32 = BEG_CHAR;
    let mut range_end: u32 = BEG_CHAR + CHUNK_SIZE as u32;
    let mut buffer: Vec<u8> = vec![0; CHUNK_SIZE];
    let mut chunk: String = String::new();
    let mut file = File::open(SYSTEM_ARRAY_LOCATION).unwrap();

    // ! idiot profing
    let range_len = range_end - range_start;

    if range_len < CHUNK_SIZE as u32 {
        halt("Invalid secret chunk legnth");
    }

    // reading chunks and crating hashes
    loop {
        file.seek(SeekFrom::Start(range_start as u64))
            .expect("Failed to set seak head");

        // Break loop if we try to read outside of the usable chunk data
        if range_start > END_CHAR {
            break;
        }

        match file.read_exact(&mut buffer) {
            Ok(_) => {
                // ! reading buffer and hasing

                for data in buffer.iter() {
                    chunk += &format!("{:02X}", data);
                }

                let chunk_hash: &str = &create_hash(&chunk);

                let chunk_map: ChunkMap = ChunkMap {
                    location: SYSTEM_ARRAY_LOCATION.to_string(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash.to_string(),
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };

                // ! Making the map path
                let mut chunk_map_path: String = String::new();
                chunk_map_path.push_str(PUBLIC_MAP_DIRECTORY);
                chunk_map_path.push_str("/chunk_");
                chunk_map_path.push_str(&String::from(chunk_number.to_string()));
                chunk_map_path.push_str(".map");
                unexist(&chunk_map_path);

                let pretty_chunk_map = serde_json::to_string_pretty(&chunk_map).unwrap();

                // ? Writing the maps
                let mut chunk_map_file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .append(true)
                    .open(chunk_map_path)
                    .expect("File could not written to");

                if let Err(_e) = write!(chunk_map_file, "{}", pretty_chunk_map) {
                    warn("Could not write json data to file");
                    return false;
                }
            }
            Err(_) => break,
        }

        output("BLUE", ".");
        if chunk_number % 17 == 0 { output("YELLOW", "*"); }
        // ? restting the indexs
        chunk_number += 1;
        chunk = "".to_string();
        range_start = range_end;
        range_end += CHUNK_SIZE as u32;
    }

    output("BLUE", "\n");
    append_log("Indexed system array !");
    notice("Indexed system array");
    return true;
}

pub fn auth_user_key() -> String {
    // ! patched to just used fixed key
    append_log("user key authentication request started");

    let password_0 = PRE_DEFINED_USERKEY;

    // ? turning password_0 into the pbkey
    let salt: String = fetch_chunk(1);
    let num: u32 = "95180".parse().expect("Not a number!");
    let iteration = std::num::NonZeroU32::new(num).unwrap();
    let mut password_key = [0; 16]; // Setting the key size

    pbkdf2::derive(
        PBKDF2_ALG,
        iteration,
        salt.as_bytes(),
        password_0.as_bytes(),
        &mut password_key,
    );

    let userkey = hex::encode(&password_key);
    let secret: String = "The hotdog man isn't real !?".to_string();
    // ! make the read the userkey from the map in the future
    let verification_ciphertext: String = read_to_string(USER_KEY_LOCATION).expect("Couldn't read the map file");

    let verification_result: String = decrypt(verification_ciphertext.to_string(), userkey.clone());

    if verification_result == secret {
        return userkey;
    } else {
        append_log("Authentication request failed");
        halt("Auth error");
        return "".to_string(); // ! i want to do unconvetional things here
    }
}

// public for encrypt.rs
pub fn array_arimitics() -> u32 {
    let chunk_data_len: u32 = ARRAY_LEN;
    let total_chunks: u32 = chunk_data_len / CHUNK_SIZE as u32;
    return total_chunks;
}

pub fn fetch_chunk(num: u32) -> String {
    // ! Reads and validates map. return the chunk data

    let upper_limit: u32 = array_arimitics();
    let lower_limit: u32 = 1;

    match num {
        0 => {
            let mut rng = rand::thread_rng();
            let range = Uniform::new(lower_limit, upper_limit);
            let map_num: u32 = range.sample(&mut rng);
            return anyways(map_num);
        },
        _ => {
            let map_num: u32 = num;
            return anyways(map_num);
        }        
    }

    fn anyways(map_num: u32) -> String{

        // ? Assembeling the path
        let mut map_path: String = String::new();
        map_path.push_str(PUBLIC_MAP_DIRECTORY);
        map_path.push_str("/chunk_");
        map_path.push_str(&String::from(map_num.to_string()));
        map_path.push_str(".map");

        // ? Reading the map
        let mut map_file = File::open(map_path).expect("File could not be opened");
        let mut map_data: String = String::new();

        map_file
            .read_to_string(&mut map_data)
            .expect("Could not read the map file !");

        // ? unpacking to the chunk map struct
        let pretty_map_data: ChunkMap = serde_json::from_str(&map_data).unwrap();

        // ? Running safety checks
        if pretty_map_data.version != VERSION {
            // Throw warning about wrong version. add option to re index the the system_array
            warn("The maps used are from an older version of encore. consider running encore --reindex-system to fix this issue. (current data will be safe)");
        }

        // ? Setting parameters to read the chunk
        let chunk_start: u32 = pretty_map_data.chunk_beg;
        let chunk_end: u32 = pretty_map_data.chunk_end;
        let mut buffer: Vec<u8> = vec![0; CHUNK_SIZE];
        let mut chunk: String = String::new();
        let mut file = File::open(SYSTEM_ARRAY_LOCATION).unwrap();

        // ! param check
        let range_len = chunk_end - chunk_start;
        if range_len < CHUNK_SIZE as u32 {
            halt("Invalid secret chunk legnth");
        }

        loop {
            file.seek(SeekFrom::Start(chunk_start as u64))
                .expect("Failed to set seak head");

            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    // ! reading buffer and hasing

                    for data in buffer.iter() {
                        chunk += &format!("{:02X}", data);
                    }
                    break
                }
                Err(e) => {
                    let err: &String = &e.to_string();
                    let mut err_msg : String = String::new();
                    err_msg.push_str("An error occoured while reading the chunk data: ");
                    err_msg.push_str(&err);
                    halt(&err_msg);
                }
            }
        }

        // ? Verifing the last half 
        let chunk_hash: &String = &create_hash(&chunk);

        if &pretty_map_data.chunk_hsh != chunk_hash {
            let mut log: String = String::new();
            log.push_str("MAP NUMBER ");
            log.push_str(&String::from(pretty_map_data.chunk_num.to_string()));
            log.push_str("HAS FAILED INTEGRITY CHECKS. ");
            log.push_str("IF THIS IS INTENTIONAL use encore --reindex-system.\n");
            log.push_str("This will only re-calc the hashes of the chunks\n");
            log.push_str("If the systemkey file has been modified or tampered with \n");
            log.push_str("some data may be illegible. \n");
            log.push_str("I would recommend exporting all data to asses any loses and reinitialize");
            append_log(&log);
            halt(&log);
        }

        return chunk;
    }
}

// todo change these security goals for multi system things

pub fn create_writing_key(key: String) -> String {
    // golang compatible ????
    let mut prekey_str: String = String::new();
    prekey_str.push_str(&key);
    prekey_str.push_str(&auth_user_key());

    let prekey = create_hash(&prekey_str);
    
    let salt: String = fetch_chunk(1);
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
