use logging::append_log;
use rand::distributions::Distribution;
use rand::distributions::Uniform;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use system::errors::ErrorArray;
use system::errors::ErrorArrayItem;
use system::errors::Errors as SE;
use system::errors::OkWarning;
use system::errors::UnifiedResult as uf;
use system::errors::WarningArray;
use system::errors::WarningArrayItem;
use system::functions::create_hash;
use system::functions::open_file;
use system::types::PathType;

use crate::array::{array_arimitics, ChunkMap};
use crate::config::CHUNK_SIZE;
use crate::local_env::SystemPaths;
use crate::local_env::VERSION;
use crate::PROGNAME;

pub fn fetch_chunk(num: u32, errors: ErrorArray) -> uf<String> {
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

    return fetch_chunk_by_number(map_num, errors);
}

fn fetch_chunk_by_number(map_num: u32, mut errors: ErrorArray) -> uf<String> {
    let warnings = WarningArray::new_container();
    let system_paths: SystemPaths = SystemPaths::new();
    let map_path: PathType =
        PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, map_num));

    // if data is return then we verify it
    match read_map_data(&map_path, errors.clone()).uf_unwrap() {
        Ok(data) => {
            let pretty_map_data: ChunkMap = match parse_map_data(&data, errors.clone()).uf_unwrap()
            {
                Ok(c) => c,
                Err(e) => return uf::new(Err(e)),
            };

            match verify_map_version(&pretty_map_data, warnings, errors.clone()).uf_unwrap() {
                Ok(d) => d.warning.display(),
                Err(e) => return uf::new(Err(e)),
            };

            let chunk = match read_chunk_data(&pretty_map_data, errors.clone()).uf_unwrap() {
                Ok(d) => d,
                Err(e) => return uf::new(Err(e)),
            };

            match verify_chunk_integrity(&chunk, &pretty_map_data, errors.clone()).uf_unwrap() {
                Ok(_) => return uf::new(Ok(chunk)),
                Err(e) => return uf::new(Err(e)),
            };
        }
        Err(e) => return uf::new(Err(e)),
    };
}

fn read_map_data(map_path: &PathType, mut errors: ErrorArray) -> uf<String> {
    // Get the file ref from the os if it exists
    let mut map_file: File = match File::open(map_path) {
        Ok(d) => d,
        Err(e) => {
            let _ = append_log(unsafe { PROGNAME }, &e.to_string(), errors.clone());
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    // reading the data if the file above exists
    let mut map_buf: String = String::new();
    let _ = match map_file.read_to_string(&mut map_buf) {
        Ok(_) => (),
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    uf::new(Ok(map_buf))
}

fn parse_map_data(map_data: &str, mut errors: ErrorArray) -> uf<ChunkMap> {
    match serde_json::from_str(map_data) {
        Ok(d) => return uf::new(Ok(d)),
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    }
}

fn verify_map_version(
    pretty_map_data: &ChunkMap,
    mut warnings: WarningArray,
    errors: ErrorArray,
) -> uf<OkWarning<()>> {
    match pretty_map_data.version == VERSION {
        true => return uf::new(Ok(OkWarning{
            data: (),
            warning: warnings,
        })),
        false => {
            match append_log(unsafe { PROGNAME }, &format!(
                "The maps used are from an older version of recs. \n --reindex-system[NOT IMPLEMENTED YET] to fix this issue. (current data will be safe)"
            ), errors.clone()).uf_unwrap(){
                Ok(_) => {
                    warnings.push(WarningArrayItem::new(system::errors::Warnings::OutdatedVersion));
                    return uf::new(Ok(OkWarning{
                                    data: (),
                                    warning: warnings,
                                }))
                },
                Err(e) => return uf::new(Err(e)),
            }
        }
    };
}

fn read_chunk_data(pretty_map_data: &ChunkMap, mut errors: ErrorArray) -> uf<String> {
    let system_paths: SystemPaths = SystemPaths::new();
    let chunk_start: u32 = pretty_map_data.chunk_beg;
    let chunk_end: u32 = pretty_map_data.chunk_end;
    let mut buffer: Vec<u8> = vec![0; CHUNK_SIZE as usize];

    let mut _chunk = String::new(); // TODO make an array or something for this val
    let mut file = match open_file(system_paths.SYSTEM_ARRAY_LOCATION, errors.clone()).uf_unwrap() {
        Ok(d) => d,
        Err(e) => return uf::new(Err(e)),
    };

    if (chunk_end - chunk_start) < CHUNK_SIZE as u32 {
        // TODO figure out how to get rid of this
        let _ = append_log(
            unsafe { PROGNAME },
            "Invalid secret chunk length",
            errors.clone(),
        );
    }

    loop {
        match file.seek(SeekFrom::Start(chunk_start as u64)) {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        match file.read_exact(&mut buffer) {
            Ok(_) => {
                _chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
                break;
            }
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        }
    }

    uf::new(Ok(_chunk))
}

fn verify_chunk_integrity(
    chunk: &str,
    pretty_map_data: &ChunkMap,
    mut errors: ErrorArray,
) -> uf<()> {
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
        let _ = append_log(unsafe { PROGNAME }, &log, errors.clone());
        errors.push(ErrorArrayItem::new(
            SE::InvalidMapData,
            format!("Map hash is incorrect"),
        ));
        return uf::new(Err(errors));
    };
    return uf::new(Ok(()));
}
