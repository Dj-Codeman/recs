#[path = "auth.rs"]
mod auth;
#[path = "system/config.rs"]
mod config;
#[path = "system/encrypt.rs"]
pub mod encrypt;
#[path = "enviornment.rs"]
mod local_env;
#[path = "system/secrets.rs"]
mod secret;
#[path = "system/system.rs"]
pub mod system; // make this its own library

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    process::exit,
};

use crate::{
    auth::{fetch_chunk, index_system_array, ChunkMap},
    config::{
        ARRAY_LEN, CHUNK_SIZE, DEBUG, PUBLIC_MAP_DIRECTORY, SECRET_MAP_DIRECTORY,
        SYSTEM_ARRAY_LOCATION,
    },
    encrypt::create_hash,
    local_env::set_system,
    secret::{forget, read, write},
    system::{append_log, exist, unexist, VERSION},
};

// !? Allow this as a toggle flag later
fn check_debug() {
    use std::env;
    env::set_var("RUST_BACKTRACE", "1");
}

pub fn initialize() {
    if DEBUG == true {
        check_debug();
    }

    if exist(SYSTEM_ARRAY_LOCATION) == false {
        set_system();
    }

    // toDo make a for loop to check the presents of all maps in the range
    let max_map: u32 = ARRAY_LEN / CHUNK_SIZE;

    let mut max_map_path = String::new();
    max_map_path.push_str(PUBLIC_MAP_DIRECTORY);
    max_map_path.push_str("/");
    max_map_path.push_str(&String::from(max_map.to_string()));
    max_map_path.push_str(".map");

    if !exist(&max_map_path) {
        // * to avoid heart ache if we find an existing system array we just re index it instead of deleting everything
        index_system_array();
    }
}

// Normal actions
pub fn insert(filename: String, owner: String, name: String) -> Option<bool> {
    if !write(filename, owner, name) {
        exit(1)
    }
    return Some(true);
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
    let mut secret_map_path: String = String::new();
    secret_map_path.push_str(SECRET_MAP_DIRECTORY);
    secret_map_path.push_str("/");
    secret_map_path.push_str(&owner);
    secret_map_path.push_str("-");
    secret_map_path.push_str(&name);
    secret_map_path.push_str(".json");

    if !exist(&secret_map_path) {
        return false;
    } else {
        return true;
    }
}

// Debugging and tooling

pub fn check_map(map_num: u32) -> bool {
    let _ = fetch_chunk(map_num); // using fetch chunk to validate the map data
    return true;
}

pub fn update_map(map_num: u32) -> bool {
    // ? Getting the current map data
    let mut map_path: String = String::new();
    map_path.push_str(PUBLIC_MAP_DIRECTORY);
    map_path.push_str("/chunk_");
    map_path.push_str(&String::from(map_num.to_string()));
    map_path.push_str(".map");

    // ? Reading the map
    let mut map_file = File::open(&map_path).expect("File could not be opened");
    let mut map_data: String = String::new();

    map_file
        .read_to_string(&mut map_data)
        .expect("Could not read the map file !");

    // ? unpacking to the chunk map struct
    let pretty_map_data: ChunkMap = serde_json::from_str(&map_data).unwrap();

    // ? calculating new hash
    let new_hash = create_hash(&fetch_chunk(map_num));

    //  making new map
    let new_map: ChunkMap = ChunkMap {
        location: pretty_map_data.location,
        version: VERSION.to_string(),
        chunk_num: pretty_map_data.chunk_num,
        chunk_hsh: new_hash,
        chunk_beg: pretty_map_data.chunk_beg,
        chunk_end: pretty_map_data.chunk_end,
    };

    // write the new map file
    unexist(&map_path);
    let updated_map = serde_json::to_string_pretty(&new_map).unwrap();

    let mut map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(map_file, "{}", updated_map) {
        eprintln!("An error occoured");
        append_log("Could save map data to file");
    };

    return true;
}

pub fn index_array() -> Option<bool> {
    index_system_array();
    return Some(true);
}

pub fn _get_array_props() {
    let _ = "";
}

// add import and export
