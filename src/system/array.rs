use logging::{append_log, errors::MyErrors};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
    str,
};
use system::{create_hash, del_dir, del_file, errors::SystemError, is_path};

use crate::{
    config::{ARRAY_LEN, CHUNK_SIZE},
    encrypt::create_secure_chunk,
    errors::{RecsError, RecsErrorType, RecsRecivedErrors},
    local_env::{MAPS, SYSTEM_ARRAY_LOCATION, VERSION},
    PROGNAME,
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

pub fn generate_system_array() -> Result<bool, RecsRecivedErrors> {
    match append_log(unsafe { &PROGNAME }, "Creating system array") {
        Ok(_) => (),
        Err(e) => return Err(RecsRecivedErrors::repack(e)),
    };

    // Remove the existing system array directory
    let _ = del_dir(&SYSTEM_ARRAY_LOCATION);

    // Create the system array contents
    let system_array_contents = create_system_array_contents();

    // Write the system array contents to the file
    match write_system_array_to_file(&system_array_contents) {
        Ok(_) => {
            match append_log(unsafe { &PROGNAME }, "Created system array") {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::repack(e)),
            };
            return Ok(true);
        }
        Err(e) => {
            match append_log(
                unsafe { &PROGNAME },
                &format!("Could not write the system_array to the path specified: "),
            ) {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::repack(e)),
            };
            return Err(e);
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

fn write_system_array_to_file(contents: &str) -> Result<(), RecsRecivedErrors> {
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(SYSTEM_ARRAY_LOCATION.to_owned())
    {
        Ok(mut system_array_file) => match write!(system_array_file, "{}", contents) {
            Ok(_) => return Ok(()),
            Err(e) => {
                let _ = append_log(unsafe { PROGNAME }, &e.to_string());
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorCreatingFile,
                    &e.to_string(),
                )));
            }
        },
        Err(e) => {
            let _ = append_log(unsafe { PROGNAME }, &e.to_string());
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorCreatingFile,
                &e.to_string(),
            )));
        }
    }
}

// indexing the created array

pub fn index_system_array() -> Result<bool, RecsRecivedErrors> {
    let mut chunk_number: u32 = 1;
    let mut range_start: u32 = BEG_CHAR;
    let mut range_end: u32 = BEG_CHAR + CHUNK_SIZE as u32;
    #[allow(unused_assignments)] // * cheap fix
    let mut chunk: String = String::new();

    let mut file = match File::open(SYSTEM_ARRAY_LOCATION.to_string()) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorOpeningFile,
                &e.to_string(),
            )))
        }
    };

    if (range_end - range_start) < CHUNK_SIZE as u32 {
        return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
            RecsErrorType::SecretArrayError,
            "Invalid secret chunk length",
        )));
    }

    loop {
        if range_start > END_CHAR {
            break;
        }

        match file.seek(SeekFrom::Start(range_start as u64)) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorReadingFile,
                    &format!("Failed to set seek head: {}", e.to_string()),
                )))
            }
        };

        let mut buffer = vec![0; CHUNK_SIZE as usize];
        match file.read_exact(&mut buffer) {
            Ok(_) => {
                chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
                let chunk_hash = create_hash(chunk);

                let chunk_map = ChunkMap {
                    location: SYSTEM_ARRAY_LOCATION.to_string(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash.to_string(),
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };

                let chunk_map_path = format!("{}/chunk_{}.map", *MAPS, chunk_number);

                if is_path(&chunk_map_path) {
                    match del_file(&chunk_map_path) {
                        Ok(_) => (),
                        Err(e) => return Err(RecsRecivedErrors::repack(MyErrors::SystemError(e))),
                    };
                }

                let pretty_chunk_map = match serde_json::to_string_pretty(&chunk_map) {
                    Ok(d) => d,
                    Err(e) => {
                        return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                            RecsErrorType::JsonCreationError,
                            &e.to_string(),
                        )))
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
                        return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                            system::errors::SystemErrorType::ErrorOpeningFile,
                            &e.to_string(),
                        )))
                    }
                };

                match write!(chunk_map_file, "{}", pretty_chunk_map) {
                    Ok(_) => match append_log(
                        unsafe { &PROGNAME },
                        &format!("The map file {} has been created", &chunk_map_path),
                    ) {
                        Ok(_) => (),
                        Err(e) => return Err(RecsRecivedErrors::repack(e)),
                    },
                    Err(e) => {
                        return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                            system::errors::SystemErrorType::ErrorOpeningFile,
                            &e.to_string(),
                        )))
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

    match append_log(unsafe { &PROGNAME }, "Indexed system array !") {
        Ok(_) => (),
        Err(e) => return Err(RecsRecivedErrors::repack(e)),
    };
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock functions or constants for testing
    // const PROGNAME: &str = "TEST_PROG";
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
