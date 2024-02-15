#[path = "system/array.rs"]
mod array;
#[path = "system/array_retrive.rs"]
mod array_tools;
#[path = "auth.rs"]
mod auth;
#[path = "system/config.rs"]
mod config;
#[path = "system/encrypt.rs"]
mod encrypt;
pub mod errors;
#[path = "enviornment.rs"]
mod local_env;
#[path = "system/secrets.rs"]
mod secret;
use errors::RecsRecivedErrors;
use local_env::SYSTEM_ARRAY_LOCATION;
use logging::append_log;
use secret::{read_raw, write_raw};
use system::{create_hash, del_file, is_path};

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

use crate::{
    array::{index_system_array, ChunkMap},
    array_tools::fetch_chunk,
    config::{ARRAY_LEN, CHUNK_SIZE},
    local_env::{set_system, MAPS, META, VERSION},
    secret::{forget, read, write},
};

/// Debugging should be set while initializing the lib, If no defined the default is disabled
pub static mut DEBUGGING: Option<bool> = None;

/// This value is set by set_prog it is used for logging creating paths and other functions. to handel its creation or modification use set_prog() to avoid wrapping 
pub static mut PROGNAME: &str = "";

/// Changes some mandatory logging functions and enables longer outputs in logs
pub fn set_debug(option: bool) {
    // Enables longer backtraces and enables more verbose logging
    match option {
        true => unsafe { DEBUGGING = Some(true) },
        false => unsafe { DEBUGGING = Some(false) },
    }
}

/// This function handels setting the PROGNAME variables
pub fn set_prog(data: &'static str) {
	unsafe { PROGNAME = data };
}

/// Initialize checks the progname, and debugging values snf ensure the lib is ready to function
pub fn initialize() -> Result<(), RecsRecivedErrors> {
    let debugging: bool = match unsafe { DEBUGGING } {
        Some(d) => match d {
            true => true,
            false => false,
        },
        None => false,
    };

    let debug: bool = match &debugging {
        true => {
            use std::env;
            env::set_var("RUST_BACKTRACE", "1");
            true
        }
        false => false,
    };

    match append_log(unsafe { &PROGNAME }, "RECS STARTED") {
        Ok(_) => (),
        Err(e) => return Err(RecsRecivedErrors::repack(e)),
    };

    match ensure_system_path(unsafe { &PROGNAME }, debug) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    match ensure_max_map_exists() {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    Ok(())
}

fn ensure_system_path(prog: &str, debug: bool) -> Result<(), RecsRecivedErrors> {
    match is_path(&SYSTEM_ARRAY_LOCATION) {
        true => (), // Nothing needs to be done the lib with this name has  already been initialized
        false => {
            match append_log(
                prog,
                "System array file does not exist, re initializing recs",
            ) {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::repack(e)),
            };

            match set_system(debug) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };
        }
    };
    Ok(())
}

fn ensure_max_map_exists() -> Result<(), RecsRecivedErrors> {
    let max_map = ARRAY_LEN / CHUNK_SIZE;
    let max_map_path = format!("{}/{}.map", *MAPS, max_map - 1);

    match is_path(&max_map_path) {
        true => return Ok(()),
        false => match index_system_array() {
            Ok(_) => return Ok(()),
            Err(e) => return Err(e),
        },
    };
}

// Normal actions

/// Insert takes a relative path encrypts and stores files. Weather or not they're deleted is based on values in the config.rs file 
pub fn insert(filename: String, owner: String, name: String) -> Result<(), RecsRecivedErrors> {
    match write(filename, owner, name) {
        Ok(_) => return Ok(()),
        Err(e) => return Err(e),
    }
}

/// Retrieve starts a request to decrypt the file requested on sucess it returns where the file currently is 'String' and where to file was when it was encrypted 'String' it is up to the client to decide weather to move the file there or read the contents and delete the file
pub fn retrive(owner: String, name: String, uid: u32) -> Result<(String, String), RecsRecivedErrors> {
    match read(owner, name, uid) {
        Ok((file_path, file_home, _)) => return Ok((file_path, file_home)), // TODO implement a handeler for warning
        Err(e) => return Err(e),
    }
}

pub fn remove(owner: String, name: String) -> Result<(), RecsRecivedErrors> {
    match forget(owner, name) {
        Ok(_) => return Ok(()),
        Err(e) => return Err(e),
    }
}

pub fn ping(owner: String, name: String) -> bool {
    let secret_map_path = format!("{}/{owner}-{name}.meta", *META, owner = owner, name = name);
    is_path(&secret_map_path)
}

pub fn encrypt_raw(data: String) -> Result<(String, String, usize), RecsRecivedErrors> {
    match write_raw(data.into()) {
        Ok((key, data, chunks)) => return Ok((key, data, chunks)),
        Err(e) => return Err(e),
    }
}

pub fn decrypt_raw(
    recs_data: String,
    recs_key: String,
    recs_chunks: usize,
) -> Result<Vec<u8>, RecsRecivedErrors> {
    match read_raw(recs_data, recs_key, recs_chunks) {
        Ok((_warnings, data)) => Ok(data),
        Err(e) => return Err(e),
    }
}

pub fn update_map(map_num: u32) -> bool { // Add a result to return errors from this
    // ? Getting the current map data
    let map_path: String = format!("{}/chunk_{}.map", *MAPS, map_num);

    // ? Reading the map
    let mut map_file = File::open(&map_path).expect("File could not be opened");
    let mut map_data: String = String::new();

    map_file
        .read_to_string(&mut map_data)
        .expect("Could not read the map file !");

    // ? unpacking to the chunk map struct
    let pretty_map_data: ChunkMap = serde_json::from_str(&map_data).unwrap();

    // ? calculating new hash
    let chunk_data: (bool, Option<String>) = match fetch_chunk(map_num) {
        Ok(data) => (true, Some(data)),
        Err(_) => (false, None),
    };

    let new_hash: Option<String> = match chunk_data {
        (true, None) => None,
        (true, Some(chunk)) => Some(create_hash(chunk)),
        (false, None) => None,
        (false, Some(_)) => None,
    };

    if new_hash == None {
        let _ = append_log( unsafe { &PROGNAME }, &format!("Failed to fetch chunk data for number {}", &map_num));
    }

    //  making new map
    let new_map: ChunkMap = ChunkMap {
        location: pretty_map_data.location,
        version: VERSION.to_string(),
        chunk_num: pretty_map_data.chunk_num,
        chunk_hsh: new_hash.unwrap(),
        chunk_beg: pretty_map_data.chunk_beg,
        chunk_end: pretty_map_data.chunk_end,
    };

    // write the new map file
    let _ = del_file(&map_path);
    let updated_map = serde_json::to_string_pretty(&new_map).unwrap();

    let mut map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(map_file, "{}", updated_map) {
        eprintln!("An error occoured");
        let _ = append_log(unsafe { &PROGNAME }, "Could save map data to file");
    };

    return true;
}

#[test]
fn ping_check() {
    let result = ping(unsafe { PROGNAME.to_owned() }, "dummy".to_string());
    assert_eq!(result, false);
}

// Debugging and tooling

pub fn check_map(map_num: u32) -> bool {
    // needs to fail gracefuly
    match fetch_chunk(map_num) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[test]
fn null_map() {
    let result = check_map(8000000);
    assert_eq!(result, false);
}
// only passes on un initialized systems

pub fn _get_array_props() {
    // reading part of the array
    // get version
    // add a hash somewhere
    let _ = "";
}
