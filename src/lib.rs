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
#[path = "enviornment.rs"]
mod local_env;
#[path = "system/secrets.rs"]
mod secret;

use logging::{append_log, start_log};
use pretty::{halt, warn, output};
use secret::write_raw;
use system::{del_file, is_path};

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    process::exit,
};

use crate::{
    array::{index_system_array, ChunkMap},
    array_tools::fetch_chunk,
    config::{ARRAY_LEN, CHUNK_SIZE, DEBUG, SYSTEM_ARRAY_LOCATION},
    encrypt::create_hash,
    local_env::{set_system, MAPS, META, PROG, VERSION},
    secret::{forget, read, write},
};

// !? Allow this as a toggle flag later
fn check_debug() {
    use std::env;
    env::set_var("RUST_BACKTRACE", "1");
}

pub fn initialize() {
    start_log(PROG);
    if DEBUG {
        check_debug();
    }

    ensure_system_path();
    ensure_max_map_exists();
}

fn ensure_system_path() {
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
        (true, None) => {
            eprintln!("Encryption succeded but no key was provided");
            exit(1)
        }
        (true, Some(_)) => return Some(true),
        (false, None) => exit(1),
        (false, Some(_)) => exit(1),
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

pub fn encrypt_raw(data: String) -> bool {
    let results: bool = match write_raw(data) {
        (None, None) => {
            warn("No data provided");
            false
        }
        (None, Some(_)) => {
            warn("Useless data provided");
            false
        }
        (Some(_), None) => {
            warn("Useless data provided");
            false
        }
        (Some(key), Some(data)) => {
            output(
                "BLUE",
                &format!(
                    "The requested data is as follows :\nRecs key: {}\nRecs data: {}",
                    key, data
                ),
            );
            true
        }
    };
    results
}

pub fn decrypt_raw(_recs_data: String, _recs_key: String) -> bool {
    true
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
        halt(&format!(
            "Failed to fetch chunk data for number {}",
            &map_num
        ));
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

pub fn _get_array_props() {
    // reading part of the array
    // get version
    // add a hash somewhere
    let _ = "";
}

// add import and export
