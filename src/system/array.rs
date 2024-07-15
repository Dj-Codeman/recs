use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
    str,
};
use dusa_collection_utils::{
    errors::{ErrorArray, ErrorArrayItem, Errors, UnifiedResult as uf, WarningArray},
    functions::{create_hash, del_dir, del_file, path_present},
    types::PathType,
};

use crate::{
    config::{ARRAY_LEN, CHUNK_SIZE}, encrypt::create_secure_chunk, local_env::{SystemPaths, VERSION}, log::log
};

#[derive(Serialize, Deserialize, Debug)]
pub struct ChunkMap {
    pub location: PathType,
    pub version: String,
    pub chunk_num: u32,
    pub chunk_hsh: String,
    pub chunk_beg: u32,
    pub chunk_end: u32,
}

// system array definitions
// make this more dynamic or sum like that
const BEG_CHAR: u32 = 40;
const END_CHAR: u32 = 80984; //80,999

// public for encrypt.rs
pub fn array_arimitics() -> u32 {
    let chunk_data_len: u32 = ARRAY_LEN;
    let total_chunks: u32 = chunk_data_len / CHUNK_SIZE as u32;
    return total_chunks;
}

pub fn generate_system_array(errors: ErrorArray) -> Result<(), ErrorArray> {
    let system_paths: SystemPaths = SystemPaths::new();

    // Attempt to log an initial message
    log("Generating system array".to_string());

    // Remove the existing system array directory
    if let Err(err) = del_dir(&system_paths.SYSTEM_ARRAY_LOCATION, errors.clone()).uf_unwrap() {
        err.display(false);
    };

    // Create the system array contents
    let system_array_contents = create_system_array_contents();

    // Write the system array contents to the file
    match write_system_array_to_file(&system_array_contents, errors.clone()).uf_unwrap() {
        Ok(_) => {
            // Log success message if writing to file succeeds
            log("System array file created".to_string());
            Ok(())
        },
        Err(errors) => {
            // Log error if writing to file fails and return accumulated errors
            log("Errors happened while creating the system array file".to_string());
            Err(errors)
        }
    }
}

fn create_system_array_contents() -> String {
    let system_array_header = format!("<--REcS Array Version {}-->\n", VERSION);

    let system_array_chunk = create_secure_chunk();

    let system_array_footer = "\n</--REcS Array-->";

    format!(
        "{}{}{}",
        system_array_header, system_array_chunk, system_array_footer
    )
}

pub fn write_system_array_to_file(contents: &str, mut errors: ErrorArray) -> uf<()> {
    let system_paths: SystemPaths = SystemPaths::new();

    // Attempt to open the file
    let system_array_file_result = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(system_paths.SYSTEM_ARRAY_LOCATION.to_owned())
        .map_err(|e| {
            log("Error opening system array file".to_string());
            errors.push(ErrorArrayItem::new(Errors::OpeningFile, e.to_string()));
            errors.clone()
        });

    match system_array_file_result {
        Ok(mut system_array_file) => {
            if let Err(e) = write!(system_array_file, "{}", contents) {
                log("Error while writing to the system array file".to_string());
                errors.push(ErrorArrayItem::new(Errors::CreatingFile, e.to_string()));
                return uf::new(Err(errors));
            } else {
                return uf::new(Ok(()));
            }
        }
        Err(e) => uf::new(Err(e)),
    }
}

// indexing the created array

pub fn index_system_array(mut errors: ErrorArray, warnings: WarningArray) -> uf<bool> {
    let mut chunk_number: u32 = 1;
    let mut range_start: u32 = BEG_CHAR;
    let mut range_end: u32 = BEG_CHAR + CHUNK_SIZE as u32;
    let system_paths: SystemPaths = SystemPaths::new();
    #[allow(unused_assignments)] // * cheap fix
    let mut chunk: String = String::new();

    let mut file = match File::open(system_paths.SYSTEM_ARRAY_LOCATION.to_string()) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    if (range_end - range_start) < CHUNK_SIZE as u32 {
        let err_item =
            ErrorArrayItem::new(Errors::GeneralError, "Invalid chunk legnth".to_string());
        errors.push(err_item);
        return uf::new(Err(errors));
    }

    loop {
        if range_start > END_CHAR {
            break;
        }

        match file.seek(SeekFrom::Start(range_start as u64)) {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        let mut buffer = vec![0; CHUNK_SIZE as usize];
        match file.read_exact(&mut buffer) {
            Ok(_) => {
                chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
                let chunk_hash = create_hash(chunk);

                let chunk_map = ChunkMap {
                    location: system_paths.SYSTEM_ARRAY_LOCATION.clone(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash.to_string(),
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };

                let chunk_map_path: PathType =
                    PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, chunk_number));

                if path_present(&chunk_map_path, errors.clone()).unwrap() {
                    match del_file(chunk_map_path.clone(), errors.clone(), warnings.clone())
                        .uf_unwrap()
                    {
                        Ok(_) => (),
                        Err(e) => return uf::new(Err(e)),
                    };
                }

                let pretty_chunk_map = match serde_json::to_string_pretty(&chunk_map) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };

                let mut chunk_map_file = match OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .append(true)
                    .open(&chunk_map_path)
                {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };

                match write!(chunk_map_file, "{}", pretty_chunk_map) {
                    Ok(_) => {
                        log("No Cipher Data received".to_string());
                    }
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };
            }
            Err(_) => break,
        }

        chunk_number += 1;
        // chunk = "".to_string();
        range_start = range_end;
        range_end += CHUNK_SIZE as u32;
    }

    log("No Cipher Data received".to_string());

    uf::new(Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock functions or constants for testing
    // const PROGNAME: &str = "TEST_PROG";
    
    #[test]
    fn test_create_system_array_contents() {
        let expected_header = format!("<--REcS Array Version {}-->\n", VERSION);
        let expected_footer = "\n</--REcS Array-->";

        let result = create_system_array_contents();

        assert!(result.starts_with(&expected_header));
        assert!(result.ends_with(expected_footer));
    }

    // Add more tests as needed
}
