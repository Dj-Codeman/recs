use dusa_collection_utils::{
    errors::{ErrorArrayItem, Errors, UnifiedResult as uf},
    functions::{create_hash, del_dir, del_file},
    log,
    log::LogLevel,
    stringy::Stringy,
    types::PathType,
};

use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
    str,
};

use crate::{
    config::{ARRAY_LEN, CHUNK_SIZE},
    encrypt::create_secure_chunk,
    local_env::{SystemPaths, VERSION},
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

pub async fn generate_system_array() -> Result<(), ErrorArrayItem> {
    let system_paths: SystemPaths = SystemPaths::read_current().await;

    // Attempt to log an initial message
    log!(LogLevel::Trace, "RECS: Generating system array");

    // Remove the existing system array directory
    if let Err(err) = del_dir(&system_paths.SYSTEM_ARRAY_LOCATION).uf_unwrap() {
        log!(LogLevel::Error, "{}", err);
        return Err(err);
    };

    // Create the system array contents
    let system_array_contents: Stringy = create_system_array_contents();

    // Write the system array contents to the file
    if let Err(err) = write_system_array_to_file(&system_array_contents).await {
        return Err(err);
    }
    log!(LogLevel::Trace, "RECS: System array file created");

    Ok(())
}

fn create_system_array_contents() -> Stringy {
    let system_array_header = format!("<--REcS Array Version {}-->\n", VERSION);

    let system_array_chunk = create_secure_chunk();

    let system_array_footer = "\n</--REcS Array-->";

    Stringy::from_string(format!(
        "{}{}{}",
        system_array_header, system_array_chunk, system_array_footer
    ))
}

pub async fn write_system_array_to_file(contents: &str) -> Result<(), ErrorArrayItem> {
    let system_paths = SystemPaths::read_current().await;

    // Open the file with simplified error mapping and chaining
    let mut system_array_file = OpenOptions::new()
        .create(true) // Using `create(true)` instead of `create_new(true)` allows overwriting
        .write(true)
        .append(true)
        .open(system_paths.SYSTEM_ARRAY_LOCATION.to_owned())
        .map_err(ErrorArrayItem::from)?;

    // Write to the file directly and handle any potential errors
    write!(system_array_file, "{}", contents).map_err(|e| {
        log!(
            LogLevel::Error,
            "Error while writing to the system array file: {:?}",
            e
        );
        ErrorArrayItem::from(e)
    })?;

    Ok(())
}

// indexing the created array
pub async fn index_system_array() -> uf<bool> {
    let system_paths = SystemPaths::read_current().await;
    let mut chunk_number: u32 = 1;
    let mut range_start: u32 = BEG_CHAR;
    let mut range_end: u32 = BEG_CHAR + CHUNK_SIZE as u32;

    // Validate initial range to ensure it's correct
    if (range_end - range_start) < CHUNK_SIZE as u32 {
        return uf::new(Err(ErrorArrayItem::new(
            Errors::GeneralError,
            "Invalid chunk length".to_string(),
        )));
    }

    // Attempt to open the file for reading
    let mut file = match File::open(system_paths.SYSTEM_ARRAY_LOCATION.clone()) {
        Ok(file) => file,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };

    while range_start <= END_CHAR {
        // Seek to the start of the chunk and handle errors
        if let Err(err) = file.seek(SeekFrom::Start(range_start as u64)) {
            return uf::new(Err(ErrorArrayItem::from(err)));
        }

        let mut buffer: Vec<u8> = vec![0; CHUNK_SIZE as usize];
        match file.read_exact(&mut buffer) {
            Ok(_) => {
                let chunk: String = buffer.iter().map(|byte| format!("{:02X}", byte)).collect();
                let chunk_hash = create_hash(chunk);

                let chunk_map = ChunkMap {
                    location: system_paths.SYSTEM_ARRAY_LOCATION.clone(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash,
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };

                // Construct path for the chunk map file
                let chunk_map_path =
                    PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, chunk_number));

                // Delete existing chunk map file if it exists
                if chunk_map_path.exists() {
                    if let Err(err) = del_file(&chunk_map_path.clone()).uf_unwrap() {
                        return uf::new(Err(err));
                    }
                }

                // Serialize chunk map and handle potential serialization errors
                let pretty_chunk_map = match serde_json::to_string_pretty(&chunk_map) {
                    Ok(map) => map,
                    Err(e) => {
                        return uf::new(Err(ErrorArrayItem::from(e)));
                    }
                };

                // Write the serialized chunk map to a new file
                if let Err(e) = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&chunk_map_path)
                    .and_then(|mut file| write!(file, "{}", pretty_chunk_map))
                {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }

            }
            Err(_) => break, // Break the loop on read error (EOF or other issue)
        }

        // Move to the next chunk
        chunk_number += 1;
        range_start = range_end;
        range_end += CHUNK_SIZE as u32;
    }

    log!(LogLevel::Trace, "RECS: Indexing completed successfully");
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
