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
use logging::{append_log, errors::MyErrors, start_log};
use pretty::output;
use secret::{read_raw, write_raw};
use system::{del_file, is_path};

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    process::exit,
};

use crate::{
    array::{index_system_array, ChunkMap},
    array_tools::fetch_chunk,
    config::{ARRAY_LEN, CHUNK_SIZE, SYSTEM_ARRAY_LOCATION},
    encrypt::create_hash,
    local_env::{set_system, MAPS, META, VERSION},
    secret::{forget, read, write},
};

/// Debugging should be set while initializing the lib, If no defined the default is disabled
pub static mut DEBUGGING: Option<bool> = None;

/// The PROG variable must be defined for logging, When this lib is used by diffrent programs, this will be the diffrenciator for the log files
pub static mut PROGNAME: String = String::from("undefined");

fn set_debug(option: bool) {
    // Enables longer backtraces and enables more verbose logging
    match option {
        true => unsafe { DEBUGGING = Some(true) },
        false => unsafe { DEBUGGING = Some(false) },
    }
}

pub fn initialize(prog: String) {
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
        false => {
            false
        },
    };

    match start_log(unsafe { &PROG }) {
        Ok(_) => (),
        Err(e) => RecsRecivedErrors::display(RecsRecivedErrors::repack(e), false),
    }

    ensure_system_path(unsafe { &PROG }, debug);
    ensure_max_map_exists();
}

fn ensure_system_path(prog: &str, debug: bool) {
    match is_path(SYSTEM_ARRAY_LOCATION) {
        true => todo!(),
        false => {
            append_log(prog, "System array file does not exist, re initializing recs");
            set_system(debug);
        },
    }
    
    if !is_path(SYSTEM_ARRAY_LOCATION) {

        set_system();
    }
}

fn ensure_max_map_exists() {
    let max_map = ARRAY_LEN / CHUNK_SIZE;
    let max_map_path = format!("{}/{}.map", *MAPS, max_map);

    if !is_path(&max_map_path) {
        index_system_array();
    }
}

// Normal actions
// TODO identify if exit0 is appropriate and revisit
pub fn insert(filename: String, owner: String, name: String) -> Option<bool> {
    match write(filename, owner, name) {
        (true, Some(_), Some(_)) => return Some(true),
        (true, _, _) => {
            eprintln!("Encryption succeded but proper meta data was not provided");
            exit(1)
        }
        (_, _, _) => exit(1),
    }
}

pub fn retrive(owner: String, name: String) -> Option<bool> {
    if !read(owner, name) {
        exit(1);
    }
    return Some(true);
}

pub fn remove(owner: String, name: String) -> Option<bool> {
    if !forget(owner, name) {
        exit(1);
    }
    return Some(true);
}

pub fn ping(owner: String, name: String) -> bool {
    let secret_map_path = format!("{}/{owner}-{name}.meta", *META, owner = owner, name = name);
    is_path(&secret_map_path)
}

pub fn encrypt_raw(data: String) -> (Option<String>, Option<String>, Option<usize>) {
    match write_raw(data) {
        (Some(key), Some(data), Some(chunks)) => (Some(key), Some(data), Some(chunks)),
        (None, None, None) => {
            eprintln!("No data provided");
            (None, None, None)
        }
        (_, _, _) => {
            eprintln!("Useless data provided");
            (None, None, None)
        }
    }
}

pub fn decrypt_raw(
    recs_data: String,
    recs_key: String,
    recs_chunks: usize,
) -> (Option<bool>, Option<Vec<u8>>) {
    match read_raw(recs_data, recs_key, recs_chunks) {
        (true, Some(data)) => (Some(true), Some(data)),
        (_, _) => (Some(false), None),
    }
}

pub fn update_map(map_num: u32) -> bool {
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
        Some(data) => (true, Some(data)),
        None => (false, None),
    };

    let new_hash: Option<String> = match chunk_data {
        (true, None) => None,
        (true, Some(chunk)) => Some(create_hash(&chunk)),
        (false, None) => None,
        (false, Some(_)) => None,
    };

    if new_hash == None {
        eprint!("Failed to fetch chunk data for number {}", &map_num);
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
    del_file(&map_path);
    let updated_map = serde_json::to_string_pretty(&new_map).unwrap();

    let mut map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(map_file, "{}", updated_map) {
        eprintln!("An error occoured");
        append_log(PROG, "Could save map data to file");
    };

    return true;
}

#[test]
fn ping_check() {
    let result = ping(PROG.to_string(), "dummy".to_string());
    assert_eq!(result, false);
}

// Debugging and tooling

pub fn check_map(map_num: u32) -> bool {
    // needs to fail gracefuly
    if fetch_chunk(map_num) == None {
        false
    } else {
        true
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
