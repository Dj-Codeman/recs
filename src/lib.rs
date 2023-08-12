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
#[path = "system/array.rs"]
mod array;
#[path = "system/array_retrive.rs"]
mod array_tools;

use logging::append_log;
use system::{del_file, is_path};

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    process::exit,
};

use crate::{
    array_tools::fetch_chunk,
    array::{index_system_array, ChunkMap},
    config::{
        ARRAY_LEN, CHUNK_SIZE, DEBUG,
        SYSTEM_ARRAY_LOCATION,
    },
    encrypt::create_hash,
    local_env::{set_system, PROG, VERSION, MAPS, META},
    secret::{forget, read, write},
};

// !? Allow this as a toggle flag later
fn check_debug() {
    use std::env;
    env::set_var("RUST_BACKTRACE", "1");
}

pub fn initialize() {
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
    let secret_map_path = format!(
        "{}/{owner}-{name}.json",
        *META,
        owner = owner,
        name = name
    );
    is_path(&secret_map_path)
}

#[test]
fn ping_check() {
    let result = ping(PROG.to_string(), "dummy".to_string());
    assert_eq!(result, false);
}

// Debugging and tooling

pub fn check_map(map_num: u32) -> bool {
    // needs to fail gracefuly
    let _ = fetch_chunk(map_num); // using fetch chunk to validate the map data
    return true;
}

#[test]
#[ignore = "Not implemented correctly"]
fn null_map() {
    let result = check_map(0);
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

// pub fn index_array() -> Option<bool> {
//     index_system_array();
//     return Some(true);
// }

pub fn _get_array_props() {
    // reading part of the array
    // get version
    // add a hash somewhere
    let _ = "";
}

// add import and export
