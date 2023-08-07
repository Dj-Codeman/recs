use rand::distributions::Distribution;
use logging::append_log;
use rand::distributions::Uniform;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::array::{array_arimitics, ChunkMap};
use crate::config::{SYSTEM_ARRAY_LOCATION, CHUNK_SIZE};
use crate::encrypt::create_hash;
use crate::local_env::{VERSION, PROG, MAPS};

pub fn fetch_chunk(num: u32) -> String {
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

fn fetch_chunk_by_number(map_num: u32) -> String {
    let map_path = format!("{}/chunk_{}.map", *MAPS, map_num);

    let map_data = read_map_data(&map_path);

    let pretty_map_data = parse_map_data(&map_data);

    verify_map_version(&pretty_map_data);

    let chunk = read_chunk_data(&pretty_map_data);

    verify_chunk_integrity(&chunk, &pretty_map_data);

    chunk
}

fn read_map_data(map_path: &str) -> String {
    let mut map_file = File::open(map_path).expect("File could not be opened");
    let mut map_data = String::new();
    map_file
        .read_to_string(&mut map_data)
        .expect("Could not read the map file !");
    map_data
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
