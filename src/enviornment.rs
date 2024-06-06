use logging::append_log;
use serde::{Deserialize, Serialize};
use sysinfo::{System, SystemExt};
use system::{
    errors::{ErrorArray, ErrorArrayItem, Errors as SE, Warnings as SW, OkWarning, UnifiedResult as uf, WarningArray, WarningArrayItem},
    functions::{make_dir, path_present},
    types::{ClonePath, PathType},
};

use crate::{
    array::{generate_system_array, index_system_array},
    auth::generate_user_key,
    config::STREAMING_BUFFER_SIZE,
    PROGNAME,
};

// Static stuff

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemPaths {
    pub SYSTEM_PATH: PathType,
    pub DATA: PathType,
    pub MAPS: PathType,
    pub META: PathType,
    pub SYSTEM_ARRAY_LOCATION: PathType,
    pub USER_KEY_LOCATION: PathType,
}

impl SystemPaths {
    pub fn new() -> Self {
        let system_p: PathType = PathType::Content(format!("/var/{}", unsafe { PROGNAME }));
        // /// This is where the encrypted data is kept, This is just cipherdata, paths and other meta data is kept in \'META\'
        // /// The \'SYSTEM_ARRAY\' is a big string of charathers. when an encryption operation is started a section of this file is taken to combined with the USER_KEY to derive the key used in the encryption function
        // /// This folder is where the meta data used to decrypt files is kept
        // /// This file is used in conjunction with \'USER_KEY_LOCATION\' to create the keys used for encrypting files
        // /// This is used to verify the string the system uses to derive keys from, without this file all data is ILLEGIBLE
        SystemPaths {
            SYSTEM_PATH: system_p.clone_path(),
            DATA: PathType::Content(format!("{}/secrets", system_p.clone_path())),
            MAPS: PathType::Content(format!("{}/maps", system_p.clone_path())),
            META: PathType::Content(format!("{}/meta", system_p.clone_path())),
            SYSTEM_ARRAY_LOCATION: PathType::Content(format!(
                "{}/array.recs",
                system_p.clone_path()
            )),
            USER_KEY_LOCATION: PathType::Content(format!(
                "{}/userdata.recs",
                system_p.clone_path()
            )),
        }
    }
}

// !  enviornment as in program

pub fn set_system(debug: bool, errors: ErrorArray, mut warnings: WarningArray) -> uf<OkWarning<()>> {
    // This functions is responsible for creating the dir tree,
    // It also monitors the output of the functions that create keys and indexs for them
    match make_folders(debug, errors.clone()).uf_unwrap() {
        Ok(_) => (),
        Err(e) => return uf::new(Err(e)),
    };

    match generate_system_array(errors.clone(), warnings.clone(), debug).uf_unwrap() {
        Ok(b) => {
            warnings.append(b.warning);
            match index_system_array(errors.clone(), warnings.clone(), debug).uf_unwrap() {
                Ok(d) => {
                    if let Err(_) = append_log(
                        unsafe { PROGNAME },
                        "System array has been created and indexed",
                        errors.clone(),
                    ).uf_unwrap() {
                        let w = WarningArrayItem::new_details(SW::Warning, String::from("Logging issue occoured"));
                        warnings.push(w);
                    }; 
                    warnings.append(d.warning);
                },
                Err(e) => return uf::new(Err(e)),
            }
            
        },
        Err(mut e) => {
            e.push(ErrorArrayItem { err_type: SE::GeneralError, err_mesg: String::from("Failed to generate system array") });
            return uf::new(Err(e))
        },
    }

    match generate_user_key(debug, errors.clone(), warnings.clone()).uf_unwrap() {
        Ok(_) => return uf::new(Ok(OkWarning {
            data: (),
            warning: warnings,
        })),
        Err(e) => return uf::new(Err(e)),
    }
}

// ! environment as in file paths
fn make_folders(debug: bool, mut errors: ErrorArray) -> uf<()> {
    // * Verifying path exists and creating missing ones
    let system_paths: SystemPaths = SystemPaths::new();

    match path_present(&system_paths.SYSTEM_PATH, errors.clone()).uf_unwrap() {
        Ok(b) => match b {
            true => {
                // we're ok to populate folder tree
                let mut paths: Vec<PathType> = vec![];
                paths.insert(0, system_paths.DATA.clone());
                paths.insert(1, system_paths.MAPS.clone());
                paths.insert(2, system_paths.META.clone());

                for path in paths.iter() {
                    match make_dir(&path.clone_path(), errors.clone()).uf_unwrap() {
                        Ok(_) => {
                            if debug {
                                append_log(
                                    unsafe { PROGNAME },
                                    &format!("Path : {} created", &path),
                                    errors.clone(),
                                );
                            }
                        }
                        Err(e) => return uf::new(Err(e)),
                    };
                }
            }
            false => {
                errors.push(ErrorArrayItem::new(
                    SE::CreatingFile,
                    "System path missing".to_string(),
                ));
                return uf::new(Err(errors));
            }
        },
        Err(e) => return uf::new(Err(e)),
    }
    return uf::new(Ok(()));
}

// ! environment as in system
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

// * environment as in host
