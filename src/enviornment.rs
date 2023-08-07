use nix::unistd::geteuid;
use logging::{append_log, start_log};
use sysinfo::{System, SystemExt};
use system::{is_path, del_dir, make_dir, make_dir_perm}; // for finding free ram for vectors

use crate::{
    auth::generate_user_key,
    config::{PUBLIC_MAP_DIRECTORY, SECRET_MAP_DIRECTORY, DATA_DIRECTORY, STREAMING_BUFFER_SIZE},
    array::{generate_system_array, index_system_array},
};

// Static stuff
pub const VERSION: &str = "R1.0.0"; // make this cooler in the future
pub const PROG: &str = "recs";

// !  enviornment as in program

pub fn set_system() {
    make_folders();

    if generate_system_array() == true {
        if index_system_array() == false { eprintln!("An error occoured while initializing check log"); }
    } else {
        eprintln!("An error occoured while initializing check log");
    }

    generate_user_key();

}

// ! enviornment as in file paths  

pub fn make_folders() {
    // * Verifing path exists and creating missing ones 
    let system_path = format!("/var/recs/{}/", geteuid());
    let permissions = 0o770;

    match make_dir_perm(&system_path, permissions) {
        Ok(()) => () ,
        Err(err) => eprintln!("{}", err),
    }

    let mut paths = vec![];
    paths.insert(0, DATA_DIRECTORY);
    paths.insert(1, PUBLIC_MAP_DIRECTORY);
    paths.insert(2, SECRET_MAP_DIRECTORY);

    for path in paths.iter() {
        if is_path(path) {
            del_dir(path);
            make_dir(path);
        } else {
            make_dir(path);
        }
    }

    start_log(PROG);
    append_log(PROG, "Folders recreated");
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

