// use nix::unistd::geteuid;
use lazy_static::lazy_static;
use logging::append_log;
use sysinfo::{System, SystemExt};
use system::{create_hash, make_dir}; // for finding free ram for vectors

use crate::{
    array::{generate_system_array, index_system_array},
    auth::generate_user_key,
    config::STREAMING_BUFFER_SIZE,
    errors::RecsRecivedErrors,
    PROGNAME,
};

// Static stuff
pub const VERSION: &str = "R1.0.0"; // make this cooler in the future

// semi static
lazy_static! {
    // Default rescs directory
    #[derive(Debug)]
    pub static ref SYSTEM_PATH: String = format!("/srv/recs/{}", create_hash(unsafe { PROGNAME.to_owned() }));
    // Paths for important things
    pub static ref SYSTEM_ARRAY_LOCATION: String = format!("{}/array.recs", SYSTEM_PATH.to_owned());
    pub static ref ARRAY_PATH: String = format!("/usr/recs");
    pub static ref DATA: String = format!("{}/secrets", SYSTEM_PATH.clone());
    pub static ref MAPS: String = format!("{}/maps", SYSTEM_PATH.clone());
    pub static ref META: String = format!("{}/meta", SYSTEM_PATH.clone());
}
// !  enviornment as in program

pub fn set_system(debug: bool) -> Result<(), RecsRecivedErrors> {
    // This functions is responsible for creating the dir tree,
    // It also monitors the output of the functions that create keys and indexs for them
    match make_folders(debug) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    match generate_system_array() {
        Ok(_) => {
            let _ = match index_system_array() {
                Ok(_) => append_log(
                    unsafe { &PROGNAME },
                    "System array has been created and indexed",
                ),

                Err(e) => return Err(e),
            };
        }
        Err(e) => return Err(e),
    };

    match generate_user_key(debug) {
        Ok(_) => Ok(()),
        Err(e) => return Err(e),
    }
}

// ! enviornment as in file paths

fn make_folders(debug: bool) -> Result<(), RecsRecivedErrors> {
    // * Verifing path exists and creating missing ones

    match make_dir(&SYSTEM_PATH) {
        Ok(_) => {
            // we're ok to populate folder tree
            let mut paths = vec![];
            paths.insert(0, DATA.clone());
            paths.insert(1, MAPS.clone());
            paths.insert(2, META.clone());
            paths.insert(2, ARRAY_PATH.clone());

            for path in paths.iter() {
                let _ = match make_dir(path) {
                    Ok(_) => match debug {
                        true => {
                            append_log(unsafe { &PROGNAME }, &format!("Path : {} created", &path))
                        }
                        false => Ok(()),
                    },
                    Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
                };
            }
        }
        Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
    };
    Ok(())
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
