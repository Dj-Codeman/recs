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
// pub mod errors;
#[path = "enviornment.rs"]
mod local_env;
#[path = "system/secrets.rs"]
mod secret;
use dusa_collection_utils::{
    errors::{OkWarning, UnifiedResult as uf},
    functions::{create_hash, del_file, path_present},
    log,
    log::LogLevel,
    types::PathType,
};
use local_env::VERSION;
use secret::{read_raw, write_raw};

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

use crate::{
    array::{index_system_array, ChunkMap},
    array_tools::fetch_chunk,
    config::{ARRAY_LEN, CHUNK_SIZE},
    local_env::{set_system, SystemPaths},
    secret::{forget, read, write},
};

/// Debugging should be set while initializing the lib. If not defined, the default is disabled.
pub static mut DEBUGGING: Option<bool> = None;

/// This value is set by set_prog. It is used for logging, creating paths, and other functions.
/// To handle its creation or modification, use set_prog() to avoid wrapping.
pub static mut PROGNAME: &str = "";

/// Changes some mandatory logging functions and enables longer outputs in logs
///
/// # Arguments
///
/// * `option` - A boolean value to enable or disable debugging.
pub fn set_debug(option: bool) {
    // Enables longer backtraces and enables more verbose logging
    match option {
        true => unsafe { DEBUGGING = Some(true) },
        false => unsafe { DEBUGGING = Some(false) },
    }
}

/// This function handles setting the PROGNAME variable.
///
/// # Arguments
///
/// * `data` - A static string slice representing the program name.
pub fn set_prog(data: &'static str) {
    unsafe { PROGNAME = data };
}

/// Initialize checks the progname and debugging values and ensures the lib is ready to function
///
/// # Arguments
///
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<()>` - A unified result indicating success or failure.
pub async fn initialize(temporary_path: bool) -> uf<()> {
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

    log!(LogLevel::Info, "RECS started");

    SystemPaths::set_current(temporary_path).await;

    if let Err(e) = ensure_system_path(debug).await.uf_unwrap() {
        return uf::new(Err(e));
    }

    if let Err(e) = ensure_max_map_exists().await.uf_unwrap() {
        return uf::new(Err(e));
    }

    uf::new(Ok(()))
}

/// Ensures that the system path exists, if not reinitializes it.
///
/// # Arguments
///
/// * `debug` - A boolean indicating if debugging is enabled.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<()>` - A unified result indicating success or failure.
async fn ensure_system_path(debug: bool) -> uf<()> {
    let system_paths = SystemPaths::read_current().await;

    match path_present(&system_paths.SYSTEM_ARRAY_LOCATION).uf_unwrap() {
        Ok(true) => (),
        Ok(false) => {
            log!(
                LogLevel::Info,
                "System array file does not exist, reinitialize recs"
            );
            if let Err(e) = set_system(debug).await.uf_unwrap() {
                return uf::new(Err(e));
            }
        }
        Err(e) => return uf::new(Err(e)),
    }

    uf::new(Ok(()))
}

/// Ensures that the maximum map exists, if not indexes the system array.
///
/// # Arguments
///
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<()>` - A unified result indicating success or failure.
async fn ensure_max_map_exists() -> uf<()> {
    let system_paths = SystemPaths::read_current().await;
    let max_map = ARRAY_LEN / CHUNK_SIZE;
    let max_map_path = PathType::Content(format!("{}/{}.map", system_paths.MAPS, max_map - 1));

    match path_present(&max_map_path).uf_unwrap() {
        Ok(true) => uf::new(Ok(())),
        Ok(false) => match index_system_array().await.uf_unwrap() {
            Ok(_d) => uf::new(Ok(())),
            Err(e) => return uf::new(Err(e)),
        },
        Err(e) => uf::new(Err(e)),
    }
}

/// Inserts a file by encrypting and storing it.
///
/// # Arguments
///
/// * `filename` - The relative path of the file to be stored.
/// * `owner` - The owner of the file.
/// * `name` - The name of the file.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<()>` - A unified result indicating success or failure.
pub async fn store(filename: PathType, owner: String, name: String) -> uf<()> {
    match write(filename, owner, name, false).await.uf_unwrap() {
        Ok(d) => {
            log!(LogLevel::Info, "Stored: value:{}, count: {} ", d.0, d.1);
            return uf::new(Ok(()));
        }
        Err(e) => return uf::new(Err(e)),
    }
}

/// Retrieves a file by decrypting it.
///
/// # Arguments
///
/// * `owner` - The owner of the file.
/// * `name` - The name of the file.
/// * `uid` - The unique identifier for the file.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<OkWarning<(PathType, PathType)>>` - A unified result containing the decrypted file paths or an error.
pub async fn retrieve(
    owner: String,
    name: String,
    uid: u32,
) -> uf<OkWarning<(PathType, PathType)>> {
    read(owner, name, uid, false).await
}

/// Removes a file.
///
/// # Arguments
///
/// * `owner` - The owner of the file.
/// * `name` - The name of the file.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<()>` - A unified result indicating success or failure.
pub async fn remove(owner: String, name: String) -> uf<()> {
    match forget(owner, name).await {
        Ok(_) => uf::new(Ok(())),
        Err(err) => uf::new(Err(err)),
    }
}

/// Checks if a file exists.
///
/// # Arguments
///
/// * `owner` - The owner of the file.
/// * `name` - The name of the file.
/// * `errors` - An ErrorArray to capture errors.
///
/// # Returns
///
/// * `uf<bool>` - A unified result indicating if the file exists or not.
pub async fn ping(owner: String, name: String) -> uf<bool> {
    let system_paths: SystemPaths = SystemPaths::read_current().await;
    let secret_map_path = PathType::Content(format!(
        "{}/{owner}-{name}.meta",
        system_paths.META,
        owner = owner,
        name = name
    ));
    path_present(&secret_map_path)
}

/// Encrypts raw data.
///
/// # Arguments
///
/// * `data` - The data to be encrypted.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<(String, String, usize)>` - A unified result containing the encrypted data, key, and chunk size.
pub async fn encrypt_raw(data: String) -> uf<(String, String, usize)> {
    write_raw(data.into()).await
}

/// Decrypts raw data.
///
/// # Arguments
///
/// * `recs_data` - The encrypted data.
/// * `recs_key` - The key for decryption.
/// * `recs_chunks` - The number of chunks.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `uf<OkWarning<Vec<u8>>>` - A unified result containing the decrypted data or an error.
pub fn decrypt_raw(recs_data: String, recs_key: String, recs_chunks: usize) -> uf<Vec<u8>> {
    read_raw(recs_data, recs_key, recs_chunks)
}

/// Updates the map with new data.
///
/// # Arguments
///
/// * `map_num` - The map number to be updated.
/// * `errors` - An ErrorArray to capture errors.
/// * `warnings` - A WarningArray to capture warnings.
///
/// # Returns
///
/// * `bool` - A boolean indicating if the update was successful.
pub async fn update_map(map_num: u32) -> bool {
    let system_paths: SystemPaths = SystemPaths::read_current().await;
    // Add a result to return errors from this
    // ? Getting the current map data
    let map_path: PathType =
        PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, map_num));

    // ? Reading the map
    let mut map_file = File::open(&map_path).expect("File could not be opened");
    let mut map_data: String = String::new();

    map_file
        .read_to_string(&mut map_data)
        .expect("Could not read the map file !");

    // ? unpacking to the chunk map struct
    let pretty_map_data: ChunkMap = serde_json::from_str(&map_data).unwrap();

    // ? calculating new hash
    let chunk_data: (bool, Option<String>) = match fetch_chunk(map_num).await.uf_unwrap() {
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
        log!(
            LogLevel::Error,
            "Failed to fetch chunk data for number {}",
            &map_num
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
    let _ = del_file(map_path.clone());
    let updated_map = serde_json::to_string_pretty(&new_map).unwrap();

    let mut map_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(map_path)
        .expect("File could not written to");

    if let Err(_e) = writeln!(map_file, "{}", updated_map) {
        log!(LogLevel::Error, "Could save map data to file");
    };

    return true;
}
