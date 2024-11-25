use dusa_collection_utils::{
    errors::{ErrorArrayItem, Errors, UnifiedResult as uf},
    functions::{del_file, make_dir, path_present},
    log::LogLevel,
    log,
    rwarc::LockWithTimeout,
    types::PathType,
};
use glob::glob;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sysinfo::{System, SystemExt};
use tempfile::TempDir;

use crate::{
    array::{generate_system_array, index_system_array}, auth::generate_user_key, config::STREAMING_BUFFER_SIZE, PROGNAME
};

// Static stuff
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

lazy_static! {
    static ref SYSTEM_PATH_LOCK: LockWithTimeout<SystemPaths> =
        LockWithTimeout::new(SystemPaths::new());
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPaths {
    pub SYSTEM_PATH: PathType,
    pub DATA: PathType,
    pub MAPS: PathType,
    pub META: PathType,
    pub SYSTEM_ARRAY_LOCATION: PathType,
    pub USER_KEY_LOCATION: PathType,
}

impl SystemPaths {
    /// Initializes paths based on whether they should be temporary or persistent.
    pub fn new() -> Self {
        let system_path = PathType::Content(format!("/var/{}", unsafe { PROGNAME }));

        SystemPaths {
            SYSTEM_PATH: system_path.clone(),
            DATA: PathType::Content(format!("{}/secrets", system_path.clone())),
            MAPS: PathType::Content(format!("{}/maps", system_path.clone())),
            META: PathType::Content(format!("{}/meta", system_path.clone())),
            SYSTEM_ARRAY_LOCATION: PathType::Content(format!("{}/array.recs", system_path.clone())),
            USER_KEY_LOCATION: PathType::Content(format!("{}/userdata.recs", system_path.clone())),
        }
    }

    /// Asynchronously reads the current system paths.
    pub async fn read_current() -> Self {
        let system_path_lock: LockWithTimeout<SystemPaths> = SYSTEM_PATH_LOCK.clone();
        let system_path_async = system_path_lock.try_read().await;
        match system_path_async {
            Ok(path) => path.clone(),
            Err(err) => {
                log!(LogLevel::Error, "Failed to read the system path: {}", err);
                Self::new() // Fall back to temporary paths if reading fails
            }
        }
    }

    /// Asynchronously sets the current system paths.
    pub async fn set_current(temporary: bool) {
        let system_path_lock = SYSTEM_PATH_LOCK.clone();
        let mut write_guard = system_path_lock.try_write().await.unwrap();

        let system_path = if temporary {
            log!(LogLevel::Trace, "Setting temporary file system space");
            let temp_dir = TempDir::new()
                .map_err(|err| ErrorArrayItem::from(err))
                .unwrap();
            PathType::Path(temp_dir.into_path().into())
        } else {
            PathType::Content(format!("/var/{}", unsafe { PROGNAME }))
        };

        let system_path = SystemPaths {
            SYSTEM_PATH: system_path.clone(),
            DATA: PathType::Content(format!("{}/secrets", system_path.clone())),
            MAPS: PathType::Content(format!("{}/maps", system_path.clone())),
            META: PathType::Content(format!("{}/meta", system_path.clone())),
            SYSTEM_ARRAY_LOCATION: PathType::Content(format!("{}/array.recs", system_path.clone())),
            USER_KEY_LOCATION: PathType::Content(format!("{}/userdata.recs", system_path.clone())),
        };

        *write_guard = system_path;
        log!(LogLevel::Debug, "System paths updated successfully");
    }
}

// !  environment as in program

pub async fn set_system(debug: bool) -> uf<()> {
    // This functions is responsible for creating the dir tree,
    // It also monitors the output of the functions that create keys and index for them
    if let Err(err) = make_folders(debug).await.uf_unwrap() {
        return uf::new(Err(err));
    }

    if let Err(e) = generate_system_array().await {
        return uf::new(Err(e));
    }

    if let Err(e) = index_system_array().await.uf_unwrap() {
        return uf::new(Err(e));
    }

    if let Err(e) = generate_user_key(debug).await.uf_unwrap() {
        return uf::new(Err(e));
    }

    log!(LogLevel::Trace, "System array has been created and indexed");

    uf::new(Ok(()))
}

// ! environment as in file paths
async fn make_folders(debug: bool) -> uf<()> {
    // * Verifying path exists and creating missing ones
    let system_paths: SystemPaths = SystemPaths::read_current().await;

    match path_present(&system_paths.SYSTEM_PATH).uf_unwrap() {
        Ok(b) => match b {
            true => {
                // we're ok to populate folder tree
                let mut paths: Vec<PathType> = vec![];
                paths.insert(0, system_paths.DATA.clone());
                paths.insert(1, system_paths.MAPS.clone());
                paths.insert(2, system_paths.META.clone());

                for path in paths.iter() {
                    let _ = match make_dir(&path).uf_unwrap() {
                        Ok(_) => match debug {
                            true => log!(LogLevel::Debug, "Path : {} created", &path),
                            false => (),
                        },
                        Err(e) => return uf::new(Err(e)),
                    };
                }
            }
            false => {
                return uf::new(Err(ErrorArrayItem::new(
                    Errors::GeneralError,
                    String::from("System Path missing"),
                )));
            }
        },
        Err(e) => return uf::new(Err(e)),
    }
    uf::new(Ok(()))
}

pub async fn clean_temps() -> Result<(), ErrorArrayItem> {
    let paths: SystemPaths = SystemPaths::read_current().await;
    let pattern: String = format!("{}/*.rand", paths.DATA);
    for file in glob(&pattern)
        .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.msg.to_string()))?
    {
        match file {
            Ok(path) => {
                if path.is_file() {
                    log!(LogLevel::Debug, "RECS: Deleting: {}", path.display());
                    del_file(&PathType::PathBuf(path)).uf_unwrap()?;
                }
            }
            Err(err) => return Err(ErrorArrayItem::new(Errors::GeneralError, err.to_string())),
        }
    }
    Ok(())
}

// ! environment as in system
pub fn calc_buffer() -> usize {
    let mut system = System::new_all();
    system.refresh_memory(); // Refresh only memory for better performance

    let used_ram = system.used_memory();
    let total_ram = system.total_memory();
    let free_ram = total_ram - used_ram;

    // Convert free RAM to a floating-point number for calculations
    let available_ram = free_ram as f64;

    // Calculate the buffer size with additional checks
    let buffer_size = if available_ram <= STREAMING_BUFFER_SIZE as f64 {
        // If available RAM is less than or equal to the buffer size, reduce it slightly to avoid using too much memory
        STREAMING_BUFFER_SIZE as f64 * 0.8 // Use 80% of the streaming buffer size
    } else {
        // If there is ample available RAM, increase the buffer size by a portion of the free space
        STREAMING_BUFFER_SIZE as f64 + (available_ram * 0.1) // Add 10% of the available RAM
    };

    // Ensure the buffer size is realistic and does not exceed a reasonable limit
    let max_buffer_size = 1_073_741_824; // Example: 1 GB in bytes
    let final_buffer_size = buffer_size.min(max_buffer_size as f64);

    final_buffer_size as usize // Return as a number of bytes
}

// * enviornment as in host
