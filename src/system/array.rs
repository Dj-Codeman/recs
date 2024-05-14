use logging::append_log;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{prelude::*, SeekFrom},
    str,
};
use system::{
    errors::{ErrorArray, ErrorArrayItem, Errors as SE, UnifiedResult as uf, WarningArray},
    functions::{create_hash, del_dir, del_file, open_file, path_present},
    types::PathType,
};

use crate::{
    config::{ARRAY_LEN, CHUNK_SIZE},
    encrypt::create_secure_chunk,
    local_env::{SystemPaths, VERSION},
    PROGNAME,
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

pub fn generate_system_array(mut errors: ErrorArray) -> uf<bool> {
    let system_paths: SystemPaths = SystemPaths::new();
    match append_log(unsafe { PROGNAME }, "Creating system array", errors.clone()).uf_unwrap() {
        Ok(_) => (),
        Err(e) => return uf::new(Err(e)),
    };

    // Remove the existing system array directory
    let _ = del_dir(&system_paths.SYSTEM_ARRAY_LOCATION, errors.clone());

    // Create the system array contents
    let system_array_contents = create_system_array_contents();

    // Write the system array contents to the file
    match write_system_array_to_file(&system_array_contents, errors.clone()).uf_unwrap() {
        Ok(_) => {
            match append_log(unsafe { PROGNAME }, "Created system array", errors.clone())
                .uf_unwrap()
            {
                Ok(_) => (),
                Err(e) => return uf::new(Err(e)),
            };
            return uf::new(Ok(true));
        }
        Err(e) => {
            let _ = append_log(
                unsafe { PROGNAME },
                &format!("Could not write the system_array to the path specified: "),
                errors.clone(),
            );
            return uf::new(Err(e));
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

fn write_system_array_to_file(contents: &str, mut errors: ErrorArray) -> uf<()> {
    let system_paths: SystemPaths = SystemPaths::new();

    let mut system_array_file: File =
        match open_file(system_paths.SYSTEM_ARRAY_LOCATION, errors.clone()).uf_unwrap() {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };

    match write!(system_array_file, "{}", contents) {
        Ok(d) => return uf::new(Ok(())),
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
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

    let mut file = match open_file(system_paths.SYSTEM_ARRAY_LOCATION, errors.clone()).uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };

    if (range_end - range_start) < CHUNK_SIZE as u32 {
        errors.push(ErrorArrayItem::new(
            SE::SecretArray,
            format!("Invalid secret chunk length"),
        ));
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
                    location: system_paths.SYSTEM_ARRAY_LOCATION.clone_path(),
                    version: VERSION.to_string(),
                    chunk_hsh: chunk_hash.to_string(),
                    chunk_num: chunk_number,
                    chunk_beg: range_start,
                    chunk_end: range_end,
                };

                let chunk_map_path: PathType =
                    PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, chunk_number));

                match path_present(&chunk_map_path, errors.clone()).uf_unwrap() {
                    Ok(_) => (),
                    Err(e) => match del_file(chunk_map_path, e, warnings).uf_unwrap() {
                        Ok(_) => todo!(),
                        Err(e) => return uf::new(Err(e)),
                    },
                }

                let pretty_chunk_map = match serde_json::to_string_pretty(&chunk_map) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };

                let mut chunk_map_file = match open_file(chunk_map_path, errors.clone()).uf_unwrap()
                {
                    Ok(d) => d,
                    Err(e) => return uf::new(Err(e)),
                };

                match write!(chunk_map_file, "{}", pretty_chunk_map) {
                    Ok(_) => match append_log(
                        unsafe { PROGNAME },
                        &format!("The map file {} has been created", &chunk_map_path),
                        errors.clone(),
                    )
                    .uf_unwrap()
                    {
                        Ok(_) => (),
                        Err(e) => return uf::new(Err(e)),
                    },
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

    match append_log(
        unsafe { PROGNAME },
        "Indexed system array !",
        errors.clone(),
    )
    .uf_unwrap()
    {
        Ok(_) => (),
        Err(e) => return uf::new(Err(e)),
    };
    uf::new(Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use VERSION;

    #[test]
    fn test_create_system_array_contents() {
        let expected_header = format!("<--REcS Array Version {}-->\n", VERSION);
        let expected_footer = "\n</--REcS Array-->";

        let result = create_system_array_contents();

        assert!(result.starts_with(&expected_header));
        assert!(result.ends_with(expected_footer));
    }
}
