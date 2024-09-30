use dusa_collection_utils::errors::{ErrorArray, ErrorArrayItem, Errors, UnifiedResult as uf};
use dusa_collection_utils::functions::create_hash;
use dusa_collection_utils::types::PathType;
use rand::distributions::{Distribution, Uniform};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::array::{array_arimitics, ChunkMap};
use crate::config::CHUNK_SIZE;
use crate::local_env::{SystemPaths, VERSION};
use crate::log::log;

pub fn fetch_chunk(num: u32, mut errors: ErrorArray) -> uf<String> {
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

    match fetch_chunk_by_number(map_num, &mut errors) {
        Ok(d) => uf::new(Ok(d)),
        Err(e) => {
            errors.push(e);
            uf::new(Err(errors))
        }
    }
}

fn fetch_chunk_by_number(map_num: u32, errors: &mut ErrorArray) -> Result<String, ErrorArrayItem> {
    let system_paths = SystemPaths::new();
    let map_path = PathType::Content(format!("{}/chunk_{}.map", system_paths.MAPS, map_num));

    let map_data = read_map_data(&map_path, errors)?;
    let pretty_map_data = parse_map_data(&map_data)?;
    verify_map_version(&pretty_map_data, errors)?;

    let chunk = read_chunk_data(&pretty_map_data, errors)?;
    verify_chunk_integrity(&chunk, &pretty_map_data, errors)?;

    Ok(chunk)
}

fn read_map_data(map_path: &PathType, _errors: &mut ErrorArray) -> Result<String, ErrorArrayItem> {
    let mut map_file = File::open(map_path).map_err(|e| {
        log(e.to_string());
        ErrorArrayItem::from(e)
    })?;

    let mut map_buf = String::new();
    map_file
        .read_to_string(&mut map_buf)
        .map_err(|e| ErrorArrayItem::from(e))?;

    Ok(map_buf)
}

fn parse_map_data(map_data: &str) -> Result<ChunkMap, ErrorArrayItem> {
    serde_json::from_str(map_data).map_err(|e| ErrorArrayItem::from(e))
}

fn verify_map_version(
    pretty_map_data: &ChunkMap,
    _errors: &mut ErrorArray,
) -> Result<(), ErrorArrayItem> {
    if pretty_map_data.version != VERSION {
        log(format!(
                "The maps used are from an older version of recs. \n --reindex-system[NOT IMPLEMENTED YET] to fix this issue. (current data will be safe)"
            ));
        return Err(ErrorArrayItem::new(
            Errors::GeneralError,
            "Invalid map version".to_string(),
        ));
    }

    Ok(())
}

fn read_chunk_data(
    pretty_map_data: &ChunkMap,
    _errors: &mut ErrorArray,
) -> Result<String, ErrorArrayItem> {
    let system_paths = SystemPaths::new();
    let chunk_start = pretty_map_data.chunk_beg;
    let chunk_end = pretty_map_data.chunk_end;
    let mut buffer = vec![0; CHUNK_SIZE as usize];

    let mut file =
        File::open(system_paths.SYSTEM_ARRAY_LOCATION).map_err(|e| ErrorArrayItem::from(e))?;

    if (chunk_end - chunk_start) < CHUNK_SIZE as u32 {
        log("Invalid secret chunk length".to_string());
    }

    file.seek(SeekFrom::Start(chunk_start as u64))
        .map_err(|e| ErrorArrayItem::from(e))?;

    file.read_exact(&mut buffer)
        .map_err(|e| ErrorArrayItem::from(e))?;

    let chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
    Ok(chunk)
}

fn verify_chunk_integrity(
    chunk: &str,
    pretty_map_data: &ChunkMap,
    _errors: &mut ErrorArray,
) -> Result<(), ErrorArrayItem> {
    let chunk_hash = create_hash(chunk.to_string());

    if pretty_map_data.chunk_hsh != chunk_hash {
        let log_data = format!(
            "MAP NUMBER {} HAS FAILED INTEGRITY CHECKS. IF THIS IS INTENTIONAL use encore --reindex-system.\n \
            This will only re-calc the hashes of the chunks\n \
            If the systemkey file has been modified or tampered with \n \
            some data may be illegible. \n \
            I would recommend exporting all data to assess any losses and reinitialize",
            pretty_map_data.chunk_num
        );
        log(log_data);
        return Err(ErrorArrayItem::new(
            Errors::GeneralError,
            "Chunk integrity check failed".to_string(),
        ));
    }

    return Ok(());
}
