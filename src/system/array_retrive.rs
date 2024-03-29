use logging::append_log;
use rand::distributions::Distribution;
use rand::distributions::Uniform;
use system::PathType;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use system::create_hash;
use system::errors::SystemError;

use crate::array::{array_arimitics, ChunkMap};
use crate::config::CHUNK_SIZE;
use crate::errors::RecsError;
use crate::errors::RecsErrorType;
use crate::errors::RecsRecivedErrors;
use crate::local_env::SystemPaths;
use crate::local_env::VERSION;
use crate::PROGNAME;

pub fn fetch_chunk(num: u32) -> Result<String, RecsRecivedErrors> {
    let upper_limit = array_arimitics();
    let lower_limit = 1;

    let map_num = match num {
        0 => {
            let mut rng = rand::thread_rng();
            let range = Uniform::new(lower_limit, upper_limit);
            range.sample(&mut rng)
        }
        _ => num,
    };

    return fetch_chunk_by_number(map_num);
}

fn fetch_chunk_by_number(map_num: u32) -> Result<String, RecsRecivedErrors> {
    let system_paths: SystemPaths = SystemPaths::new();
    let map_path: PathType = PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, map_num));

    // if data is return then we verify it
    match read_map_data(&map_path) {
        Ok(data) => {
            let pretty_map_data: ChunkMap = match parse_map_data(&data) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

            match verify_map_version(&pretty_map_data) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };

            let chunk = match read_chunk_data(&pretty_map_data) {
                Ok(d) => d,
                Err(e) => return Err(e),
            };
            
            match verify_chunk_integrity(&chunk, &pretty_map_data) {
                Ok(_) => return Ok(chunk),
                Err(e) => return Err(e),
            };
        }
        Err(e) => return Err(e),
    };
}

fn read_map_data(map_path: &PathType) -> Result<String, RecsRecivedErrors> {
    // Get the file ref from the os if it exists
    let mut map_file: File = match File::open(map_path) {
        Ok(d) => d,
        Err(e) => {
            let _ = append_log(unsafe { &PROGNAME }, &e.to_string());
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorOpeningFile,
                &e.to_string(),
            )));
        }
    };

    // reading the data if the file above exists
    let mut map_buf: String = String::new();
    let _ = match map_file.read_to_string(&mut map_buf) {
        Ok(_) => (),
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorReadingFile,
                &e.to_string(),
            )))
        }
    };

    Ok(map_buf)
}

fn parse_map_data(map_data: &str) -> Result<ChunkMap, RecsRecivedErrors> {
    match serde_json::from_str(map_data) {
        Ok(d) => return Ok(d),
        Err(_) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::JsonReadingError,
            )))
        }
    }
}

fn verify_map_version(pretty_map_data: &ChunkMap) -> Result<(), RecsRecivedErrors> {
    match pretty_map_data.version == VERSION {
        true => return Ok(()),
        false => {
            let _ = append_log(unsafe { &PROGNAME }, &format!(
                "The maps used are from an older version of recs. \n --reindex-system[NOT IMPLEMENTED YET] to fix this issue. (current data will be safe)"
            ));
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidMapVersion,
            )));
        }
    };
}

fn read_chunk_data(pretty_map_data: &ChunkMap) -> Result<String, RecsRecivedErrors> {
    let system_paths: SystemPaths = SystemPaths::new();
    let chunk_start = pretty_map_data.chunk_beg;
    let chunk_end = pretty_map_data.chunk_end;
    let mut buffer = vec![0; CHUNK_SIZE as usize];

    // #[allow(unused_assignments)] // * cheap fix
    let mut _chunk = String::new(); // TODO make an array or something for this val
    let mut file = match File::open(system_paths.SYSTEM_ARRAY_LOCATION) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorOpeningFile,
                &e.to_string(),
            )))
        }
    };

    if (chunk_end - chunk_start) < CHUNK_SIZE as u32 {
        // TODO figure out how to get rid of this
        let _ = append_log(unsafe { &PROGNAME }, "Invalid secret chunk length");
    }

    loop {
        match file.seek(SeekFrom::Start(chunk_start as u64)) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorReadingFile,
                    &format!("Failed to set seek head: {}", e.to_string()),
                )))
            }
        };

        match file.read_exact(&mut buffer) {
            Ok(_) => {
                _chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
                break;
            }
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::InvalidMapData,
                    &e.to_string(),
                )));
            }
        }
    }

    Ok(_chunk)
}

fn verify_chunk_integrity(chunk: &str, pretty_map_data: &ChunkMap) -> Result<(), RecsRecivedErrors> {
    let chunk_hash: &str = &create_hash(chunk.to_string());

    if &pretty_map_data.chunk_hsh != chunk_hash {
        let log = format!(
            "MAP NUMBER {} HAS FAILED INTEGRITY CHECKS. IF THIS IS INTENTIONAL use encore --reindex-system.\n \
            This will only re-calc the hashes of the chunks\n \
            If the systemkey file has been modified or tampered with \n \
            some data may be illegible. \n \
            I would recommend exporting all data to assess any losses and reinitialize",
            pretty_map_data.chunk_num
        );
        let _ = append_log(unsafe { &PROGNAME }, &log);
        return Err(RecsRecivedErrors::RecsError(RecsError::new(RecsErrorType::InvalidMapHash)));
    };
    Ok(())
}
