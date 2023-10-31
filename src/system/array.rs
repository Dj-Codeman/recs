use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
    str,
};
use logging::append_log;
use serde::{Serialize, Deserialize};
use system::{del_dir, is_path, del_file};

use crate::{
    config::{
        ARRAY_LEN, CHUNK_SIZE, SYSTEM_ARRAY_LOCATION,
    },
    local_env::MAPS,
    encrypt::{create_hash, create_secure_chunk}, local_env::{PROG, VERSION},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct ChunkMap {
    pub location: String,
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

pub fn generate_system_array() -> bool {
    append_log(PROG, "Creating system array");

    // Remove the existing system array directory
    del_dir(&SYSTEM_ARRAY_LOCATION);

    // Create the system array contents
    let system_array_contents = create_system_array_contents();

    // Write the system array contents to the file
    if write_system_array_to_file(&system_array_contents) {
        append_log(PROG, "Created system array");
        true
    } else {
        eprintln!("An error occurred");
        append_log(PROG, "Could not write the system_array to the path specified");
        false
    }
}

fn create_system_array_contents() -> String {
    let system_array_header = format!(
        "<--REcS System Array Version {}-->\n",
        VERSION
    );

    let system_array_chunk = create_secure_chunk();

    let system_array_footer = "\n</--REcS System Array-->";

    format!(
        "{}{}{}",
        system_array_header, system_array_chunk, system_array_footer
    )
}

fn write_system_array_to_file(contents: &str) -> bool {
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(SYSTEM_ARRAY_LOCATION)
    {
        Ok(mut system_array_file) => {
            if let Err(_) = write!(system_array_file, "{}", contents) {
                false
            } else {
                true
            }
        }
        Err(_) => false,
    }
}

// indexing the created array

pub fn index_system_array() -> bool {
    let mut chunk_number: u32 = 1;
    let mut range_start: u32 = BEG_CHAR;
    let mut range_end: u32 = BEG_CHAR + CHUNK_SIZE as u32;
    #[allow(unused_assignments)] // * cheap fix
    let mut chunk: String = String::new();

    let mut file = File::open(SYSTEM_ARRAY_LOCATION).expect("Failed to open file");

    if (range_end - range_start) < CHUNK_SIZE as u32 {
        eprintln!("An error occurred");
        append_log(PROG, "Invalid secret chunk length");
        return false;
    }

    loop {
        if range_start > END_CHAR {
            break;
        }

        file.seek(SeekFrom::Start(range_start as u64))
            .expect("Failed to set seek head");

        let mut buffer = vec![0; CHUNK_SIZE as usize];
        match file.read_exact(&mut buffer) {
            Ok(_) => {
                chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
                let chunk_hash = create_hash(&chunk);

                let chunk_map = ChunkMap {
                    location: SYSTEM_ARRAY_LOCATION.to_string(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash.to_string(),
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };

                let chunk_map_path = format!(
                    "{}/chunk_{}.map",
                    *MAPS,
                    chunk_number
                );

                if is_path(&chunk_map_path) {
                    del_file(&chunk_map_path);
                }

                let pretty_chunk_map =
                    serde_json::to_string_pretty(&chunk_map).expect("JSON serialization failed");

                let mut chunk_map_file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .append(true)
                    .open(&chunk_map_path)
                    .expect("File could not be written to");

                if let Err(_) = write!(chunk_map_file, "{}", pretty_chunk_map) {
                    eprintln!("An error occurred");
                    append_log(PROG, "Could not write the system_array to the path specified");
                    return false;
                }
            }
            Err(_) => break,
        }

        chunk_number += 1;
        // chunk = "".to_string();
        range_start = range_end;
        range_end += CHUNK_SIZE as u32;
    }

    append_log(PROG, "Indexed system array !");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock functions or constants for testing
    // const PROG: &str = "TEST_PROG";
    const VERSION: &str = "1.0.0"; // Adjust the version as needed

    #[test]
    fn test_create_system_array_contents() {
        let expected_header = format!("<!--REcS System Array Version {}-->\n", VERSION);
        let expected_footer = "\n</--REcS System Array-->";

        let result = create_system_array_contents();

        assert!(result.starts_with(&expected_header));
        assert!(result.ends_with(expected_footer));
    }

    // Add more tests as needed
}