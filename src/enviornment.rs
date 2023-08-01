use std::fs::{create_dir_all, remove_dir_all};
use sysinfo::{System, SystemExt}; // for finding free ram for vectors

use crate::{
    system::{output, notice, pass, halt, VERSION, HELP, append_log, start_log}, 
    auth::{generate_system_array, generate_user_key, index_system_array},
    config::{PUBLIC_MAP_DIRECTORY, SECRET_MAP_DIRECTORY, DATA_DIRECTORY, STREAMING_BUFFER_SIZE},
};

// !  enviornment as in program
pub fn version() {
    let mut ver: String = String::new();
    ver.push_str("Version ");
    ver.push_str(VERSION);
    notice(&ver);
}

pub fn show_help() {
    notice(HELP);
}

pub fn initialize() {
    make_folders();

    if generate_system_array() == true {
        if index_system_array() == false { halt("Could not index the system array !"); }
    } else {
        halt("An error occoured while creating the system array");
    }

    generate_user_key();

    pass("System initialized");
}

// ! enviornment as in file paths 

pub fn make_folders() {
    // * Verifing path exists and creating missing ones 
    // ! RUNS EVERY RUN TIME
    output("GREEN", "Checking dir tree \n");
    create_dir_all("/var/encore").expect("making folders failed"); // make this dynamic

    let mut paths = vec![];
    paths.insert(0, DATA_DIRECTORY);
    paths.insert(1, PUBLIC_MAP_DIRECTORY);
    paths.insert(2, SECRET_MAP_DIRECTORY);

    for path in paths.iter() {
        if std::path::Path::new(&path).exists() {
            remove_dir_all(path).expect("Deleting the folders failed");
            create_dir_all(path).expect("making folders failed");
        } else {
            create_dir_all(path).expect("making folders failed");   
        }
    }

    start_log();
    append_log("Folders recreated");
}


// ! enviornment as in system 
// not needed for small text string it passwords
// dep at some point 
pub fn calc_buffer() -> usize {
    let mut system = System::new_all();
    system.refresh_all();

    let used_ram = system.used_memory();
    let total_ram = system.total_memory();

    let free_ram: u64 = total_ram - used_ram; // the buffer is only a few Mbs
    
    let available_ram: f64 = free_ram as f64; //

    // add more memory checks
    let buffer_size: f64 = if available_ram <= STREAMING_BUFFER_SIZE as f64 {
        STREAMING_BUFFER_SIZE - 5120.00
    } else {
        STREAMING_BUFFER_SIZE + 5120.00 // ! should be buff size plus some divison of free space
    };

    return buffer_size as usize; // number of bytess
}

// * enviornment as in host 

