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
#[deprecated(since = "0.1.0", note = "please use `custom_error` instead")]
pub mod errors;
#[path = "enviornment.rs"]
mod local_env;
#[path = "system/secrets.rs"]
mod secret;
use local_env::VERSION;
use logging::append_log;
use secret::{read_raw, write_raw};
use system::{
    errors::{
        ErrorArray, ErrorArrayItem, OkWarning, Warnings as SW, UnifiedResult as uf, WarningArray, WarningArrayItem,
    },
    functions::{create_hash, del_file, path_present},
    types::{ClonePath, PathType},
};

use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

use crate::{
    array::ChunkMap,
    array_tools::fetch_chunk,
    config::{ARRAY_LEN, CHUNK_SIZE},
    local_env::{set_system, SystemPaths},
    secret::{forget, read, write},
};

/// Debugging should be set while initializing the lib, If no defined the default is disabled
pub static mut DEBUGGING: Option<bool> = None;

/// This value is set by set_prog it is used for logging creating paths and other functions. to handel its creation or modification use set_prog() to avoid wrapping
pub static mut PROGNAME: &'static str = "";

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
pub fn initialize(errors: ErrorArray, mut warnings: WarningArray) -> uf<OkWarning<()>> {
    let debugging: bool = match unsafe { DEBUGGING } {
        Some(d) => match d {
            true => {
                let w = WarningArrayItem::new_details(
                    system::errors::Warnings::Warning,
                    String::from("Verbosity enabled"),
                );
                warnings.push(w);
                true
            }
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

    if let Err(_) = append_log(unsafe { PROGNAME }, "RECS STARTED", errors.clone()).uf_unwrap() {
        let w = WarningArrayItem::new_details(SW::Warning, String::from("Logging issue occurred"));
        warnings.push(w);
    }

    match ensure_system_path(unsafe { PROGNAME }, debug, errors.clone(), warnings.clone())
        .uf_unwrap()
    {
        Ok(_) => (),
        Err(e) => return uf::new(Err(e)),
    };

    match ensure_max_map_exists(errors.clone()).uf_unwrap() {
        Ok(_) => (),
        Err(e) => return uf::new(Err(e)),
    };

    return uf::new(Ok(OkWarning{
        data: (),
        warning: warnings,
    }));
}

fn ensure_system_path(
    prog: &str,
    debug: bool,
    errors: ErrorArray,
    mut warnings: WarningArray,
) -> uf<OkWarning<()>> {
    let system_paths: SystemPaths = SystemPaths::new();

    if debug {
        let w = WarningArrayItem::new_details(
            system::errors::Warnings::Warning,
            format!("Current system paths are {:#?}", system_paths.clone()),
        );
        warnings.push(w);
    }

    

    match path_present(&system_paths.USER_KEY_LOCATION, errors.clone()).uf_unwrap() {
        Ok(d) => match d {
            true => {
                return uf::new(Ok(OkWarning {
                    data: (),
                    warning: warnings,
                }))
            }
            false => {
                if let Err(_) = append_log(prog, "User key file does not exist", errors.clone()).uf_unwrap() {
                    let w = WarningArrayItem::new_details(SW::Warning, String::from("Logging issue occurred"));
                    warnings.push(w);
                }

                match set_system(debug, errors.clone(), warnings.clone()).uf_unwrap() {
                    Ok(_) => (),
                    Err(e) => return uf::new(Err(e)),
                };
                return uf::new(Ok(OkWarning{
                    data: (),
                    warning: warnings,
                }));
            }
        },
        Err(e) => return uf::new(Err(e)),
    }
}

fn ensure_max_map_exists(errors: ErrorArray) -> uf<()> {
    let system_paths: SystemPaths = SystemPaths::new();
    let max_map = ARRAY_LEN / CHUNK_SIZE;
    let max_map_path = PathType::Content(format!("{}/{}.map", system_paths.MAPS, max_map - 1));

    match path_present(&max_map_path, errors.clone()).uf_unwrap() {
        Ok(_) => return uf::new(Ok(())),
        Err(e) => return uf::new(Err(e)),
    }
}

// Normal actions

/// Insert takes a relative path encrypts and stores files. Weather or not they're deleted is based on values in the config.rs file
pub fn insert(filename: PathType, owner: String, name: String, errors: ErrorArray, warnings: WarningArray) -> uf<()> {
    match write(filename, owner, name, false, errors, warnings).uf_unwrap() { // ! set fixed key to false when done
        Ok(_) => return uf::new(Ok(())),
        Err(e) => return uf::new(Err(e)),
    }
}

/// Retrieve starts a request to decrypt the file requested on sucess it returns where the file currently is 'String' and where to file was when it was encrypted 'String' it is up to the client to decide weather to move the file there or read the contents and delete the file
pub fn retrieve(
    owner: String,
    name: String,
    uid: u32,
    errors: ErrorArray,
    warnings: WarningArray,
) -> uf<(PathType, PathType)> {
    match read(owner, name, uid, false, errors, warnings).uf_unwrap() {
        Ok(d) => {
            d.warning.display();
            return uf::new(Ok(d.data));
        }
        Err(e) => return uf::new(Err(e)),
    }
}

pub fn remove(owner: String, name: String, errors: ErrorArray, warnings: WarningArray) -> uf<()> {
    match forget(owner, name, errors, warnings).uf_unwrap() {
        Ok(_) => return uf::new(Ok(())),
        Err(e) => return uf::new(Err(e)),
    }
}

pub fn ping(owner: String, name: String, errors: ErrorArray) -> uf<bool> {
    let system_paths: SystemPaths = SystemPaths::new();
    let secret_map_path = PathType::Content(format!(
        "{}/{owner}-{name}.meta",
        system_paths.META,
        owner = owner,
        name = name
    ));
    path_present(&secret_map_path, errors)
}

pub fn encrypt_raw(
    data: String,
    errors: ErrorArray,
    warnings: WarningArray,
) -> uf<(String, String, usize)> {
    match write_raw(data.into(), errors, warnings).uf_unwrap() {
        Ok((key, data, chunks)) => return uf::new(Ok((key, data, chunks))),
        Err(e) => return uf::new(Err(e)),
    }
}

pub fn decrypt_raw(
    recs_data: String,
    recs_key: String,
    recs_chunks: usize,
    errors: ErrorArray,
    warnings: WarningArray,
) -> uf<Vec<u8>> {
    match read_raw(recs_data, recs_key, recs_chunks, errors, warnings).uf_unwrap() {
        Ok(d) => {
            d.warning.display();
            return uf::new(Ok(d.data));
        }
        Err(e) => return uf::new(Err(e)),
    }
}

pub fn update_map(map_num: u32, mut errors: ErrorArray, warnings: WarningArray) -> uf<bool> {
    let system_paths: SystemPaths = SystemPaths::new();
    // Add a result to return errors from this
    // ? Getting the current map data
    let map_path: PathType =
        PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, map_num));

    // ? Reading the map
    let mut map_file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(false)
        .open(map_path.clone())
    {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };
    let mut map_data: String = String::new();

    map_file
        .read_to_string(&mut map_data)
        .expect("Could not read the map file !");

    // ? unpacking to the chunk map struct
    let pretty_map_data: ChunkMap = serde_json::from_str(&map_data).unwrap();

    // ? calculating new hash
    let chunk_data: (bool, Option<String>) = match fetch_chunk(map_num, errors.clone(), warnings.clone()).uf_unwrap()
    {
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
        let _ = append_log(
            unsafe { PROGNAME },
            &format!("Failed to fetch chunk data for number {}", &map_num),
            errors.clone(),
        );
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
    let _ = del_file(map_path.clone_path(), errors.clone(), warnings.clone());
    let updated_map = serde_json::to_string_pretty(&new_map).unwrap();

    let mut map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(map_file, "{}", updated_map) {
        eprintln!("An error occoured");
        let _ = append_log(
            unsafe { PROGNAME },
            "Could save map data to file",
            errors.clone(),
        );
    };

    return uf::new(Ok(true));
}

pub fn check_map(map_num: u32, errors: ErrorArray, warnings: WarningArray) -> uf<bool> {
    // needs to fail gracefuly
    match fetch_chunk(map_num, errors, warnings).uf_unwrap() {
        Ok(_) => return uf::new(Ok(true)),
        Err(_) => return uf::new(Ok(false)),
    }
}

// Debugging and tooling
pub fn _get_array_props() {
    unimplemented!();
    // reading part of the array
    // get version
    // add a hash somewhere
}
