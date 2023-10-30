use logging::append_log;
use pretty::warn;
use rand::distributions::Distribution;
use rand::distributions::Uniform;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::array::{array_arimitics, ChunkMap};
use crate::config::{CHUNK_SIZE, SYSTEM_ARRAY_LOCATION};
use crate::encrypt::create_hash;
use crate::local_env::{MAPS, PROG, VERSION};

pub fn fetch_chunk(num: u32) -> Option<String> {
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

fn fetch_chunk_by_number(map_num: u32) -> Option<String> {
    let map_path = format!("{}/chunk_{}.map", *MAPS, map_num);

    // if data is return then we verify it
    let chunk: Option<String> = match read_map_data(&map_path) {
        (true, None) => None,
        (true, Some(data)) => {
            // verify map data
            let pretty_map_data = parse_map_data(&data);
            verify_map_version(&pretty_map_data);

            let chunk = read_chunk_data(&pretty_map_data);
            verify_chunk_integrity(&chunk, &pretty_map_data);
            Some(chunk)
        }
        (false, None) => None,
        (false, Some(_)) => None,
    };

    chunk
}

fn read_map_data(map_path: &str) -> (bool, Option<String>) {
    // Get the file ref from the os is it exists
    let optional_map_file: Option<File> = match File::open(map_path) {
        Ok(d) => Some(d),
        Err(e) => {
            warn(&format!("{}", e));
            None
        }
    };

    // reading the data if the file above exists
    let optional_map_data: Option<String> = match optional_map_file {
        Some(mut file_ref) => {
            // defining a buffer to unpack data to
            let mut file_data_buffer: String = String::new();

            match file_ref.read_to_string(&mut file_data_buffer) {
                Ok(_) => Some(file_data_buffer), // return the buffer we just populated
                Err(_) => None,
            }
        }
        None => None,
    };

    let returning_tuple: (bool, Option<String>) = match optional_map_data {
        Some(data) => (true, Some(data)),
        None => (false, None),
    };

    returning_tuple
}

fn parse_map_data(map_data: &str) -> ChunkMap {
    serde_json::from_str(map_data).expect("JSON parsing failed")
}

fn verify_map_version(pretty_map_data: &ChunkMap) {
    if pretty_map_data.version != VERSION {
        let log = format!(
            "The maps used are from an older version of recs. \n --reindex-system[NOT IMPLEMENTED YET] to fix this issue. (current data will be safe)"
        );
        append_log(PROG, &log);
    }
}

fn read_chunk_data(pretty_map_data: &ChunkMap) -> String {
    let chunk_start = pretty_map_data.chunk_beg;
    let chunk_end = pretty_map_data.chunk_end;
    let mut buffer = vec![0; CHUNK_SIZE as usize];

    #[allow(unused_assignments)] // * cheap fix
    let mut chunk = String::new();
    let mut file = File::open(SYSTEM_ARRAY_LOCATION).unwrap();

    if (chunk_end - chunk_start) < CHUNK_SIZE as u32 {
        eprintln!("Invalid secret chunk length");
    }

    loop {
        file.seek(SeekFrom::Start(chunk_start as u64))
            .expect("Failed to set seek head");

        match file.read_exact(&mut buffer) {
            Ok(_) => {
                chunk = buffer.iter().map(|data| format!("{:02X}", data)).collect();
                break;
            }
            Err(e) => {
                let err = &e.to_string();
                let err_msg = format!("An error occurred while reading the chunk data: {}", err);
                append_log(PROG, &err_msg);
                eprintln!("{}", &err_msg);
            }
        }
    }

    chunk
}

fn verify_chunk_integrity(chunk: &str, pretty_map_data: &ChunkMap) {
    let chunk_hash: &str = &create_hash(&chunk.to_string());

    if &pretty_map_data.chunk_hsh != chunk_hash {
        let log = format!(
            "MAP NUMBER {} HAS FAILED INTEGRITY CHECKS. IF THIS IS INTENTIONAL use encore --reindex-system.\n \
            This will only re-calc the hashes of the chunks\n \
            If the systemkey file has been modified or tampered with \n \
            some data may be illegible. \n \
            I would recommend exporting all data to assess any losses and reinitialize",
            pretty_map_data.chunk_num
        );
        append_log(PROG, &log);
        eprintln!("An error has occurred; check logs");
    }
}
