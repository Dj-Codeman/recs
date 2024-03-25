use hex::encode;
use logging::append_log;
use nix::unistd::{chown, Uid};
use pretty::warn;
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use std::{
    fs::{canonicalize, metadata, read_to_string, File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
};
use system::{
    create_hash, del_dir, del_file, errors::{SystemError, SystemErrorType}, path_present, truncate, ClonePath, PathType
};

// self and create are user made code
use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    auth::create_writing_key,
    encrypt::{decrypt, encrypt},
    errors::{
        RecsError, RecsErrorType, RecsRecivedErrors, RecsRecivedWarnings, RecsWarning,
        RecsWarningType,
    },
    local_env::{calc_buffer, SystemPaths, VERSION},
    DEBUGGING, PROGNAME,
};

// ! This is the struct for all secrets CHANGE WITH CARE
#[derive(Serialize, Deserialize, Debug)]
struct SecretDataIndex {
    version: String,
    name: String,
    owner: String,
    key: u32,
    unique_id: String,
    file_path: PathType,
    secret_path: PathType,
    buffer_size: usize,
    chunk_count: usize,
    full_file_hash: String,
}

pub fn write(
    filename: PathType,
    secret_owner: String,
    secret_name: String,
    fixed_key: bool,
) -> Result<(String, usize), RecsRecivedErrors> {
    // String is key data, The u16 is the chunk cound
    //TODO Dep or simplyfy
    let max_buffer_size = calc_buffer();
    let file_size: u64 = match metadata(&filename) {
        Ok(d) => d.len(),
        Err(e) => {
            warn(&e.to_string());
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorReadingFile,
                &e.to_string(),
            )));
        }
    };
    // We're are trying to balance the speed and performance here
    // The buffer is defined semi-dynamically to allow systems like the sere to run while also taking advanted
    // Of systems with a bigger amounts of ram, Currently I don't actually know if the way this buffer is desinged
    // accomplishes what it's supposed to but as long as it compiles ill take it

    // * The size of the buffer has to be bigger than the file size because it's expanded
    // * by reading it as bytes
    let fit_buffer: usize = match (file_size).try_into() {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidBufferFit,
                &e.to_string(),
            )))
        }
    };
    let buffer_size: usize = if fit_buffer <= max_buffer_size {
        fit_buffer
    } else {
        fit_buffer / 2 // TODO make sure this doesnot fail
    };

    let msg = format!("{} '{}'", "Attempting to encrypt", &filename);
    match append_log(unsafe { &PROGNAME }, &msg) {
        Ok(_) => (),
        Err(e) => {
            warn("Error while reading logs");
            return Err(RecsRecivedErrors::repack(e));
        }
    };

    warn(&filename.to_string());
    let system_paths: SystemPaths = SystemPaths::new();


    // testing if the file exists
    let filename_existence: bool = path_present(&filename).unwrap();

    if filename_existence {
        // creating the encrypted meta data file
        let secret_map_path: PathType =
            PathType::Content(format!("{}/{}-{}.meta", system_paths.META, secret_owner, secret_name));

        // ? picking a chunk number
        let upper_limit: u32 = array_arimitics();
        let lower_limit: u32 = 1;

        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let range: Uniform<u32> = Uniform::new(lower_limit, upper_limit);
        let num: u32 = range.sample(&mut rng);

        // creating the rest of the struct data
        let unique_id: String =
            truncate(&encode(create_hash(filename.to_string())), 20).to_string();
        let canon_path: PathType = match canonicalize(&filename) {
            Ok(d) => PathType::PathBuf(d),
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorReadingFile,
                    &e.to_string(),
                )))
            }
        };

        // create the secret path
        let secret_path: PathType = PathType::Content(format!("{}/{}.recs", system_paths.DATA, unique_id));

        // Determining chunk amount and size
        let chunk_count: usize = file_size as usize / buffer_size;
        // make a hash
        let full_file_hash: String = create_hash(filename.to_string());

        // Creating the struct
        let secret_data_struct: SecretDataIndex = SecretDataIndex {
            version: String::from(VERSION),
            name: String::from(&secret_name),
            owner: String::from(&secret_owner),
            key: num,
            unique_id,
            file_path: canon_path,
            secret_path: secret_path.clone(),
            buffer_size: buffer_size as usize,
            chunk_count,
            full_file_hash,
        };

        // formatting the json data
        let pretty_data_map: Vec<u8> = match serde_json::to_vec_pretty(&secret_data_struct) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::JsonCreationError,
                    &e.to_string(),
                )))
            }
        };
        let cipher_data_map: String = match encrypt(
            pretty_data_map,
            match fetch_chunk_helper(1) {
                Ok(d) => d.into(),
                Err(e) => return Err(e),
            },
            1024,
        ) {
            // ! system files like keys and maps are set to 1024 for buffer to make reading simple
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        // TODO Stream this data with the buffer functions we have already
        let mut file = match File::open(&filename) {
            Ok(f) => f,
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorOpeningFile,
                    &e.to_string(),
                )))
            }
        };

        // defining the initial pointer range and sig chunk
        let mut buffer: Vec<u8> = vec![0; buffer_size];
        let mut encoded_buffer = String::new();
        let mut signature_count: usize = 01;
        let mut range_start: u64 = 0;
        let mut range_end: u64 = buffer_size as u64;

        // ! making the secret path to append data too
        let mut secret_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(&secret_path);

        match secret_file {
            Ok(_) => {
                let _ = append_log(
                    unsafe { &PROGNAME },
                    &format!("File created: {}", &secret_path),
                );
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = append_log(
                    unsafe { &PROGNAME },
                    &format!("The file already exists {}", &secret_path),
                );
                return Err(RecsRecivedErrors::RecsError(RecsError::new(
                    RecsErrorType::Error,
                )));
            }
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::Error,
                    &e.to_string(),
                )));
            }
        }

        // ! reading the chunks
        loop {
            let _range_len = range_end - range_start; // ? maybe store this to make reading simpeler
                                                      // Setting the pointer and cursors before the read
            match file.seek(SeekFrom::Start(range_start as u64)) {
                Ok(d) => d,
                Err(e) => {
                    return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                        system::errors::SystemErrorType::ErrorReadingFile,
                        &format!("Failed to set seek head: {}", e.to_string()),
                    )))
                }
            };

            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    for data in buffer.iter() {
                        encoded_buffer += &format!("{:02X}", data);
                    }
                    // create chunk signature
                    let sig_data = format!(
                        "{}-{}-{}-{}",
                        padding_count(signature_count), // Fix for single digit signature count
                        VERSION,
                        truncate(&create_hash(encoded_buffer.clone()), 20),
                        signature_count
                    );

                    // hexing all the data for handeling
                    let signature: String = hex::encode(sig_data);
                    // * Running the actual encryption
                    let secret_buffer = match encrypt(
                        encoded_buffer.as_bytes().to_vec(),
                        match create_writing_key(
                            match fetch_chunk_helper(num) {
                                Ok(d) => d,
                                Err(e) => return Err(e),
                            },
                            fixed_key,
                        ) {
                            // TODO ^ Simplyfy this. It is I/o intensive needed multiple files calls multiple times a second
                            Ok(d) => d.into(),
                            Err(e) => return Err(e),
                        },
                        buffer_size,
                    ) {
                        Ok(d) => d,
                        Err(e) => return Err(e),
                    };

                    // this is the one var thatll be pushed to file
                    let mut processed_chunk: String = String::new();
                    processed_chunk.push_str(&signature);
                    processed_chunk.push_str(&secret_buffer);
                    // ! THIS IS WHERER THE FILE IS OPENED

                    let result: Result<(), RecsRecivedErrors> = match secret_file.as_mut() {
                        Ok(file) => write!(file, "{}", processed_chunk).map_err(|_| {
                            RecsRecivedErrors::SystemError(SystemError::new(
                                SystemErrorType::ErrorOpeningFile,
                            ))
                        }),
                        Err(e) => Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                            RecsErrorType::Error,
                            &e.to_string(),
                        ))),
                    };

                    if let Err(e) = result {
                        match e {
                            RecsRecivedErrors::LoggerError(ed) => {
                                let _ = append_log(
                                    unsafe { &PROGNAME },
                                    &format!("UNUSED: an error occoured while logging: {:?}", ed),
                                );
                                return Err(RecsRecivedErrors::LoggerError(ed));
                            }
                            RecsRecivedErrors::SystemError(ed) => {
                                let _ = append_log(
                                    unsafe { &PROGNAME },
                                    &format!(
                                        "A system error has occoured while writing to file: {:?}",
                                        ed
                                    ),
                                );
                                return Err(RecsRecivedErrors::SystemError(ed));
                            }
                            RecsRecivedErrors::RecsError(ed) => {
                                let _ = append_log(
                                    unsafe { &PROGNAME },
                                    &format!("RECS ERROR: {:?}", ed),
                                );
                                return Err(RecsRecivedErrors::RecsError(ed));
                            }
                        }
                    };

                    // * DONE RUN THE NEXT CHUNK */
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // reached end of file
                    let _ = append_log(
                        unsafe { &PROGNAME },
                        &format!("Finished reading data from {}", &filename),
                    );
                    break;
                }
                Err(e) => {
                    return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                        RecsErrorType::Error,
                        &e.to_string(),
                    )))
                }
            }

            //? updating the pointers and the sig num
            range_start = range_end.clone();
            range_end += buffer_size as u64;
            signature_count += 1;

            // ! New data would be appended if this isn't reset per chunk read
            encoded_buffer = "".to_string();
        }

        // writting to secret data json file
        let mut secret_map_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(secret_map_path);

        // TODO ERROR HANDELING
        match secret_map_file {
            Ok(_) => match append_log(&unsafe { &PROGNAME }, "new secret map created") {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::repack(e)),
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match del_dir(&secret_path) {
                    Ok(_) => (),
                    Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
                };
                match append_log( &unsafe { &PROGNAME }, "The json associated with this file id already exists. Nothing has been deleted.") {
                    Ok(_) => (),
                    Err(e) => return Err(RecsRecivedErrors::repack(e)),
                };
                return Err(RecsRecivedErrors::SystemError(SystemError::new(
                    system::errors::SystemErrorType::ErrorCreatingFile,
                )));
            }
            Err(_) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorCreatingFile,
                    "An error occoured while creating maps",
                )));
            }
        };

        match write!(
            match secret_map_file.as_mut() {
                Ok(d) => d,
                Err(e) =>
                    return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                        RecsErrorType::Error,
                        &e.to_string()
                    ))),
            },
            "{}",
            cipher_data_map
        ) {
            Ok(()) => (),
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::Error,
                    &format!("Couldn't write encrypted data {}", &e.to_string()),
                )))
            }
        };

        // resolving the key data
        let key_data: String = match create_writing_key(
            match fetch_chunk_helper(num) {
                Ok(d) => d,
                Err(e) => return Err(e),
            },
            fixed_key,
        ) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        return Ok((key_data, chunk_count));
    } else {
        let _ = append_log(
            unsafe { &PROGNAME },
            &format!("Warning {} doesn't exist", &filename),
        );
        return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
            SystemErrorType::ErrorOpeningFile,
            &format!("Warning {} doesn't exist", &filename),
        )));
    }
}

pub fn write_raw(data: Vec<u8>) -> Result<(String, String, usize), RecsRecivedErrors> {
    // Key_Data Cipher_Data Chunk_Count
    let dummy_path: PathType = PathType::Str("/tmp/dummy.recs".into());
    let dummy_owner: &str = "owner";
    let dummy_name: &str = "temp";
    // write the data to the file
    let system_paths: SystemPaths = SystemPaths::new();


    // ! making the secret path to append data too
    let mut dummy_file: File = match File::create(dummy_path.clone_path()) {
        Ok(f) => f,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                SystemErrorType::ErrorOpeningFile,
                &format!("Couldn't create the temp file: {}", e),
            )))
        }
    };

    // writing when made
    match dummy_file.write_all(&data) {
        Ok(_) => (),
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                SystemErrorType::ErrorOpeningFile,
                &format!("Error while reading dummy file: {:?}", &e.to_string()),
            )))
        }
    };

    // encrypting the dummy file
    let results: Result<(String, usize), RecsRecivedErrors> = write(
        dummy_path,
        dummy_owner.to_string(),
        dummy_name.to_string(),
        true,
    );

    match results {
        Ok((data, count)) => {
            // got the key now get the cipher data
            let key: String = data;
            // finding the dummy map
            let secret_map_path: PathType =
                PathType::Content(format!("{}/{}-{}.meta", system_paths.META, dummy_owner, dummy_name));
            // decrypting and reading
            let cipher_map_data: String = match read_to_string(secret_map_path) {
                Ok(d) => d,
                Err(e) => {
                    return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                        system::errors::SystemErrorType::ErrorOpeningFile,
                        &e.to_string(),
                    )))
                }
            };
            let key_data: String = match fetch_chunk_helper(1) {
                Ok(d) => d,
                Err(e) => return Err(e),
            };

            let secret_map_data: Vec<u8> = match decrypt(&cipher_map_data, &key_data) {
                Ok(d) => d,
                Err(e) => return Err(e),
            };
            let secret_map: SecretDataIndex =
                match serde_json::from_str(&String::from_utf8_lossy(&secret_map_data)) {
                    Ok(d) => d,
                    Err(e) => {
                        return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                            RecsErrorType::JsonReadingError,
                            &format!(
                                "Json data decrypted in write function was garbage: {:?}, {}",
                                &secret_map_data, e
                            ),
                        )))
                    }
                };
            // pulling info from the map
            // ensure the data is there
            match path_present(&secret_map.secret_path) {
                Ok(b) => match b {
                    true => (),
                    false => {
                        let _ = append_log(
                            unsafe { &PROGNAME },
                            "THE DATA FILE SPECIFIED DOES NOT EXIST",
                        );
                        return Err(RecsRecivedErrors::RecsError(RecsError::new(
                            RecsErrorType::Error,
                        )));
                    },
                },
                Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
            }


            // reading and printing the file
            let recs_data: String = match read_to_string(&secret_map.secret_path) {
                Ok(data) => data.replace("\n", ""),
                Err(e) => {
                    return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                        SystemErrorType::ErrorReadingFile,
                        &e.to_string(),
                    )))
                }
            };

            match forget(dummy_owner.to_owned(), dummy_name.to_owned()) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };

            return Ok((key, recs_data, count));
        }
        Err(e) => return Err(e),
    }
}

pub fn read_raw(
    data: String,
    key: String,
    chunks: usize,
) -> Result<(Vec<Option<RecsRecivedWarnings>>, Vec<u8>), RecsRecivedErrors> {
    // Recreating the cipher chunk size
    let secret_size: usize = data.chars().count();
    let secret_divisor: usize = chunks;
    let new_buffer_size: usize = secret_size / secret_divisor;

    // * Defing the initial parameters to start reading from string
    // defining the initial pointer range and sig chunk

    let mut range_start: usize = 0;
    let mut range_end: usize = new_buffer_size as usize;
    let mut signature_count: usize = 1;

    let mut encoded_buffer: Vec<u8> = vec![]; // decrypted hex encoded data
    let mut plain_buffer: Vec<u8> = vec![]; // Because now we encrypt and decryt to bytes we dont give af about utf8 data
    let mut signature: String = String::new(); // the decoded signature

    // ! reading the chunks
    loop {
        // Setting the pointer and cursors before the read

        // ! handeling the file reading and outputs
        while range_start < data.len() {
            let chunk: &str = &data[range_start..range_end];
            let secret_buffer: String = match std::str::from_utf8(chunk.as_bytes()) {
                // This function is reading the hex data from the file, It SHOULD be a string
                Ok(s) => s.to_owned(),
                Err(e) => {
                    return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                        RecsErrorType::InvalidUtf8Data,
                        &e.to_string(),
                    )))
                }
            };

            // take the first spliiting chunk into signature and cipher data
            let encoded_signature: &str = truncate(&secret_buffer, 64);
            // ! When this inevidably fails, Remember the paddingcount() changes the sig legnth.
            let cipher_buffer: &str = &secret_buffer[64..]; // * this is the encrypted hex encoded bytes

            // * decrypting the chunk
            let mut decrypted_data: Vec<u8> = match decrypt(&cipher_buffer, &key) {
                Ok(d) => d, // TODO find a more efficient way to do this
                Err(e) => return Err(e),
            };

            encoded_buffer.append(&mut decrypted_data);

            // * handeling decoding the signature
            // ? This mess decodes the vec array into a hex encoded string, then reads that into a normal &string

            let signature_utf8: Result<String, std::string::FromUtf8Error> =
                String::from_utf8(match hex::decode(encoded_signature) {
                    Ok(d) => d,
                    Err(e) => {
                        return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                            RecsErrorType::InvalidHexData,
                            &format!(
                                "An error occoured while reading signature {}",
                                &e.to_string()
                            ),
                        )))
                    }
                });

            let signature_data: String = match signature_utf8 {
                Ok(d) => d,
                Err(e) => {
                    return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                        RecsErrorType::InvalidUtf8Data,
                        &format!(
                            "An error occoured while reading signature {}",
                            &e.to_string()
                        ),
                    )))
                }
            };

            signature += &signature_data;

            // ! After 9 chuncks an HMAC error is thrown because the sig size is not updated
            // ! ^ This should be remedied
            // !? Verify the signature integrity
            match verify_signature(&encoded_buffer, signature.as_str(), signature_count) {
                Ok(w) => {
                    // * This is where the decoded bytes are retrived
                    let mut plain_result: Vec<u8> = match hex::decode(encoded_buffer.clone()) {
                        Ok(d) => d,
                        Err(e) => {
                            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                RecsErrorType::InvalidTypeGiven,
                                &e.to_string(),
                            )))
                        }
                    };

                    //? updating the pointers and the buffer
                    plain_buffer.append(&mut plain_result);
                    // ? ranges
                    range_start = range_end.clone();
                    range_end += new_buffer_size as usize;
                    signature_count += 1;
                    encoded_buffer.clear();
                    signature = "".to_string();

                    match range_start >= secret_size {
                        true => return Ok((w, plain_buffer)),
                        false => (),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// The read function decrypts the data in a temporary path, It will return The path the the file decrypted, The location of the file when it was encrypted, and a Vec<Options<Warning>> if anything non fatal happend
pub fn read(
    secret_owner: String,
    secret_name: String,
    owner_uid: u32,
    fixed_key: bool,
) -> Result<(PathType, PathType, Vec<Option<RecsRecivedWarnings>>), RecsRecivedErrors> {
    // creating the secret json path
    match append_log(unsafe { &PROGNAME }, "Decrypting request") {
        Ok(_) => (),
        Err(e) => return Err(RecsRecivedErrors::repack(e)),
    };
    let system_paths: SystemPaths = SystemPaths::new();
    let secret_map_path: PathType = PathType::Content(format!("{}/{}-{}.meta", system_paths.META, secret_owner, secret_name));

    let secret_json_existence: bool = secret_map_path.to_path_buf().exists();
    if secret_json_existence {
        let cipher_map_data: String =
            read_to_string(secret_map_path).expect("Couldn't read the map file");
        let key_data: String = match fetch_chunk_helper(1) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        let secret_map_data = match decrypt(&cipher_map_data, &key_data) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        let secret_map: SecretDataIndex = match serde_json::from_slice(&secret_map_data) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::JsonReadingError,
                    &e.to_string(),
                )))
            }
        };

        let _ = match unsafe { DEBUGGING } {
            Some(bug) => match bug {
                true => append_log(unsafe { &PROGNAME }, &format!("{:?}", secret_map)),
                false => append_log(unsafe { &PROGNAME }, &format!("Secret map data recived")),
            },
            None => append_log(unsafe { &PROGNAME }, &format!("Secret map data recived")),
        };

        let mut warnings: Vec<Option<RecsRecivedWarnings>> = vec![None];

        // ! Validating that we can mess with this data
        warnings.push(match secret_map.version == VERSION {
            true => None,
            false => {
                let _ = append_log(
                    unsafe { &PROGNAME },
                    "Data from and older version of recs attempting to read anyway",
                );
                Some(RecsRecivedWarnings::RecsWarning(RecsWarning::new(
                    RecsWarningType::OutdatedVersion,
                )))
            }
        });

        // Creating a temp filename to write the data too so we can change the owner and
        // ensure the data is there
        let temp_name: String = match path_present(&secret_map.secret_path) {
            Ok(b) => match b {
                // This ensure the tmp path are more likely to be unique
                true => truncate(&create_hash(secret_map.secret_path.to_string())[5..], 10).to_owned(),
                false => {
                    return Err(RecsRecivedErrors::RecsError(RecsError::new(
                        RecsErrorType::InvalidFile,
                    )))
                }
            },
            Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
        };

        // really dumb way to get random int
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let tmp_path: PathType = PathType::Content(format!("/tmp/dusa_{}{:?}", temp_name, since_the_epoch.as_secs()));
        match del_file(tmp_path.clone_path()) {
            Ok(_) => (),
            Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
        };

        // generating the secret key for the file
        let writting_key: String = match create_writing_key(
            match fetch_chunk_helper(secret_map.key) {
                Ok(d) => d,
                Err(e) => return Err(e),
            },
            fixed_key,
        ) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        // Create chunk map from sig
        // ! this has to be modified to account for the second end byte
        let secret_size: usize = match metadata(&secret_map.secret_path) {
            Ok(d) => {
                if d.len() as usize == 0 {
                    let _ = append_log(
                        unsafe { &PROGNAME },
                        "The secret file has a size of zero, it is corrupted",
                    );
                    return Err(RecsRecivedErrors::RecsError(RecsError::new(
                        RecsErrorType::Error,
                    )));
                } else {
                    d.len() as usize
                }
            }
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    SystemErrorType::ErrorReadingFile,
                    &e.to_string(),
                )))
            }
        };
        let secret_divisor: usize = secret_map.chunk_count as usize;
        let new_buffer_size: usize = secret_size / secret_divisor;

        // Defing the loop to read the encrypted file
        let mut file = match File::open(&secret_map.secret_path) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    SystemErrorType::ErrorOpeningFile,
                    &e.to_string(),
                )))
            }
        };
        // defining the initial pointer range and sig chunk
        let mut buffer: Vec<u8> = vec![0; new_buffer_size];

        let mut range_start: u64 = 0;
        let mut range_end: u64 = new_buffer_size as u64;
        let mut signature_count: usize = 1;

        // ! defing buffer and data that can leave loops
        let mut encoded_buffer: Vec<u8> = vec![]; // decrypted hex encoded data
        let mut signature: String = String::new(); // the decoded signature

        // // // * checking if its safe to make the file

        // Opening plain file to write too
        let mut plain_file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(&tmp_path)
        {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    SystemErrorType::ErrorCreatingFile,
                    &e.to_string(),
                )))
            }
        };

        // ! reading the chunks
        loop {
            // Setting the pointer and cursors before the read
            match file.seek(SeekFrom::Start(range_start as u64)) {
                Ok(d) => d,
                Err(e) => {
                    return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                        system::errors::SystemErrorType::ErrorReadingFile,
                        &format!("Failed to set seek head: {}", e.to_string()),
                    )))
                }
            };

            // ! handeling the file reading and outputs
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    let secret_buffer = match std::str::from_utf8(&buffer) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                RecsErrorType::InvalidTypeGiven,
                                &e.to_string(),
                            )))
                        }
                    };

                    // take the first spliiting chunk into signature and cipher data
                    let encoded_signature: &str = truncate(&secret_buffer, 64); // 61 + how ever big the chunk count is
                    let cipher_buffer: &str = &secret_buffer[64..];

                    // * decrypting the chunk
                    let mut decrypted_data: Vec<u8> = match decrypt(&cipher_buffer, &writting_key) {
                        Ok(d) => d,
                        Err(e) => return Err(e),
                    };

                    encoded_buffer.append(&mut decrypted_data);

                    // * handeling decoding the signature
                    let signature_utf8: Result<String, std::string::FromUtf8Error> =
                        String::from_utf8(match hex::decode(encoded_signature) {
                            Ok(d) => d,
                            Err(e) => {
                                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                    RecsErrorType::InvalidHexData,
                                    &format!(
                                        "An error occoured while reading signature {}",
                                        &e.to_string()
                                    ),
                                )))
                            }
                        });

                    let signature_data: String = match signature_utf8 {
                        Ok(d) => d,
                        Err(e) => {
                            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                RecsErrorType::InvalidUtf8Data,
                                &format!(
                                    "An error occoured while reading signature {}",
                                    &e.to_string()
                                ),
                            )))
                        }
                    };

                    signature += &signature_data
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => {
                    match append_log(unsafe { &PROGNAME }, &e.to_string()) {
                        Ok(_) => (),
                        Err(e) => return Err(RecsRecivedErrors::repack(e)),
                    };
                    return Err(RecsRecivedErrors::RecsError(RecsError::new(
                        RecsErrorType::Error,
                    )));
                }
            }

            // ! After 9 chuncks an HMAC error is thrown because the sig size is not updated
            // ! ^ This should be remedied
            // !? Verify the signature integrity
            // let _sig_digit_count = truncate(&signature, 1);
            match verify_signature(&encoded_buffer, signature.as_str(), signature_count) {
                Ok(mut w) => {
                    // ? unencoding buffer
                    // * This is where the decoded bytes are retrived
                    let plain_result: Vec<u8> = match hex::decode(encoded_buffer.clone()) {
                        Ok(d) => d,
                        Err(e) => {
                            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                RecsErrorType::InvalidTypeGiven,
                                &e.to_string(),
                            )))
                        }
                    };

                    // ? appending on decode
                    match plain_file.write_all(&plain_result) {
                        Ok(_) => (),
                        Err(e) => {
                            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                                SystemErrorType::ErrorOpeningFile,
                                &e.to_string(),
                            )))
                        }
                    }

                    //? updating the pointers and the buffer
                    range_start = range_end.clone();
                    range_end += new_buffer_size as u64;
                    signature_count += 1;
                    encoded_buffer.clear();
                    signature = "".to_string();
                    // ? appending any warning
                    warnings.append(&mut w)
                }
                Err(e) => return Err(e),
            }
        }
        let _ = append_log(
            unsafe { &PROGNAME },
            &format!(
                "Decrypting request: {} has been decrypted !",
                &secret_map.file_path
            ),
        );
        // changing file owner
        let safe_path = match canonicalize(&tmp_path) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::InvalidFile,
                    &e.to_string(),
                )))
            }
        };

        match chown(&safe_path, Some(Uid::from_raw(owner_uid)), None) {
            Ok(_) => return Ok((tmp_path, secret_map.file_path, warnings)), // return the temporary path and let the client handel it
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::Error,
                    &e.to_string(),
                )))
            }
        }
        // moving to the right dir
        // secret_map.file_path
    } else {
        let _ = append_log(unsafe { &PROGNAME }, "The secret map doen't exist");
        return Err(RecsRecivedErrors::RecsError(RecsError::new(
            RecsErrorType::InvalidMapData,
        )));
    }
}

pub fn forget(secret_owner: String, secret_name: String) -> Result<(), RecsRecivedErrors> {
    // creating the secret json file
    let _ = append_log(unsafe { &PROGNAME }, "Forgetting secret");
    let system_paths: SystemPaths = SystemPaths::new();
    let secret_map_path = PathType::Content(format!("{}/{}-{}.meta", system_paths.META, secret_owner, secret_name));

    // testing if the secret json exists before starting encryption
    if path_present(&secret_map_path).map_err(|e| RecsRecivedErrors::SystemError(e))? {
        let cipher_map_data: String = match read_to_string(&secret_map_path) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::JsonReadingError,
                    &e.to_string(),
                )))
            }
        };

        let key_data: String = match fetch_chunk_helper(1) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        let secret_map_data = match decrypt(&cipher_map_data, &key_data) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        let secret_map: SecretDataIndex = match serde_json::from_slice(&secret_map_data) {
            Ok(d) => d,
            Err(e) => {
                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                    RecsErrorType::JsonReadingError,
                    &e.to_string(),
                )))
            }
        };

        if path_present(&secret_map.secret_path).map_err(|e| RecsRecivedErrors::SystemError(e))? {
            match del_file(secret_map.secret_path) {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
            };
        }
        match del_file(secret_map_path.clone_path()) {
            Ok(_) => {
                _ = append_log(
                    unsafe { PROGNAME },
                    &format!("{} has been deleted", &secret_map_path),
                )
            }
            Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
        };

        return Ok(());
    } else {
        match append_log(unsafe { &PROGNAME }, "The file requested doesn't exist") {
            Ok(_) => (),
            Err(e) => return Err(RecsRecivedErrors::repack(e)),
        };
        return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
            RecsErrorType::Error,
            "The requested file doesn't exist",
        )));
    }
}

// * helper funtion for fetching chunks
fn fetch_chunk_helper(num: u32) -> Result<String, RecsRecivedErrors> {
    match fetch_chunk(num) {
        Ok(d) => return Ok(d),
        Err(e) => return Err(e),
    }
}

fn verify_signature(
    encoded_buffer: &Vec<u8>,
    signature: &str,
    signature_count: usize,
) -> Result<Vec<Option<RecsRecivedWarnings>>, RecsRecivedErrors> {
    let _sig_digit_count = truncate(&signature, 1); // remember it exists

    let sig_version = truncate(&signature[3..], 6);

    // Defining one variable that will hold the last warning if any
    let mut warnings: Vec<Option<RecsRecivedWarnings>> = vec![];

    warnings.push( match sig_version == VERSION {
        true => None,
        false => {
            let _ = append_log(unsafe { &PROGNAME }, "I'll try to read this data but if a can't, get an older version or recs or encore and try again");
            Some(RecsRecivedWarnings::RecsWarning(RecsWarning::new(
                RecsWarningType::OutdatedVersion,
            )))
        }
    });

    let new_hash_data: String = match String::from_utf8(encoded_buffer.to_vec()) {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidTypeGiven,
                &e.to_string(),
            )))
        }
    };
    // pulling the hash from the signature
    let sig_hash: String = truncate(&signature[10..], 20).to_owned();
    let new_hash: String = truncate(&create_hash(new_hash_data.clone()), 20).to_owned();

    warnings.push(match sig_hash == new_hash {
        true => None,
        false => {
            let _ = append_log(unsafe { &PROGNAME }, "A chunk had an invalid has signature");
            match append_log(
                unsafe { &PROGNAME },
                "an option will be in a cli tool to ignore checks in an emergency",
            ) {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::repack(e)),
            };
            return Err(RecsRecivedErrors::RecsError(RecsError::new(
                RecsErrorType::InvalidSignature,
            )));
        }
    });

    let sig_count = match signature[31..].parse::<usize>() {
        Ok(d) => d,
        Err(e) => {
            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                RecsErrorType::InvalidTypeGiven,
                &e.to_string(),
            )))
        }
    };

    warnings.push(match sig_count == signature_count {
        true => None,
        false => Some(RecsRecivedWarnings::RecsWarning(RecsWarning::new(
            RecsWarningType::MisAlignedChunk,
        ))),
    });

    let _ = append_log(
        unsafe { &PROGNAME },
        &format!(
            "Decrypting request: {} signatures verified, writing",
            &new_hash
        ),
    );
    return Ok(warnings);
}

fn padding_count(number: usize) -> String {
    // TODO Add support for a chunck count of usize
    if number < 10 {
        let mut number_string = String::new();
        number_string.push_str("0");
        number_string.push_str(&number.to_string());
        return number_string;
    } else {
        let number_string: String = String::from(&number.to_string());
        return number_string;
    }
}
