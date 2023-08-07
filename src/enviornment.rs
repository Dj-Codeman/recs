// use nix::unistd::geteuid;
use lazy_static::lazy_static;
use logging::{append_log, start_log};
use sysinfo::{System, SystemExt};
use system::{is_path, del_dir, make_dir, make_dir_perm}; // for finding free ram for vectors

use crate::{
    auth::generate_user_key,
    config::STREAMING_BUFFER_SIZE,
    array::{generate_system_array, index_system_array}, encrypt::create_hash,
};

// Static stuff
pub const VERSION: &str = "R1.0.0"; // make this cooler in the future
pub const PROG: &str = "recs";// THIS HAS TO BE DEFINED SOMEWHERE ELSE


// semi static
lazy_static! {
    // Default rescs directory
    pub static ref SYSTEM_PATH: String = format!("/srv/recs/{}", create_hash(&PROG.to_string()));
    // Paths for important things
    pub static ref DATA: String = format!("{}/secrets", SYSTEM_PATH.clone()); 
    pub static ref MAPS: String = format!("{}/maps", SYSTEM_PATH.clone()); 
    pub static ref META: String = format!("{}/meta", SYSTEM_PATH.clone()); 
}
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
    let permissions = 0o770;

    match make_dir_perm(&SYSTEM_PATH, permissions) {
        Ok(()) => () ,
        Err(err) => eprintln!("{}", err),
    }

    let mut paths = vec![];
    paths.insert(0, DATA.clone());
    paths.insert(1, MAPS.clone());
    paths.insert(2, META.clone());

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

