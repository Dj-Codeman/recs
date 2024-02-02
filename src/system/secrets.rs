use hex::encode;
use logging::append_log;
use pretty::halt;
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use std::{
    fs::{canonicalize, metadata, read_to_string, File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
    path::Path,
    process::exit,
};
use system::{
    create_hash, del_dir, del_file,
    errors::{SystemError, SystemErrorType},
    is_path, truncate,
};

// self and create are user made code
use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    auth::create_writing_key,
    config::{LEAVE_IN_PEACE, SOFT_MOVE_FILES},
    encrypt::{decrypt, encrypt},
    errors::{RecsError, RecsErrorType, RecsRecivedErrors},
    local_env::{calc_buffer, DATA, META, VERSION},
    PROGNAME,
};

// ! This is the struct for all secrets CHANGE WITH CARE
#[derive(Serialize, Deserialize, Debug)]
struct SecretDataIndex {
    version: String,
    name: String,
    owner: String,
    key: u32,
    unique_id: String,
    file_path: String,
    secret_path: String,
    buffer_size: usize,
    chunk_count: usize,
    full_file_hash: String,
}

pub fn write(
    filename: String,
    secret_owner: String,
    secret_name: String,
) -> Result<(String, usize), RecsRecivedErrors> {
    // String is key data, The u16 is the chunk cound
    //TODO Dep or simplyfy
    let max_buffer_size = calc_buffer();
    let file_size = match metadata(&filename) {
        Ok(d) => d.len(),
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                system::errors::SystemErrorType::ErrorReadingFile,
                &e.to_string(),
            )))
        }
    };
    // We're are trying to balance the speed and performance here
    // The buffer is defined semi-dynamically to allow systems like the sere to run while also taking advanted
    // Of systems with a bigger amounts of ram, Currently I don't actually know if the way this buffer is desinged
    // accomplishes what it's supposed to but as long as it compiles ill take it

    let fit_buffer: usize = match (file_size / 4).try_into() {
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
        fit_buffer / 4
    };

    let msg = format!("{} '{}'", "Attempting to encrypt", &filename);
    append_log(unsafe { &PROGNAME }, &msg);

    // testing if the file exists
    let filename_existence: bool = is_path(&filename);

    if filename_existence {
        // creating the encrypted meta data file
        let secret_map_path: String = format!("{}/{}-{}.meta", *META, secret_owner, secret_name);

        // ? picking a chunk number
        let upper_limit: u32 = array_arimitics();
        let lower_limit: u32 = 1;

        let mut rng = rand::thread_rng();
        let range = Uniform::new(lower_limit, upper_limit);
        let num = range.sample(&mut rng);

        // creating the rest of the struct data
        let unique_id: String = truncate(&encode(create_hash(&filename)), 20).to_string();
        let canon_path: String = match canonicalize(&filename) {
            Ok(d) => d.display().to_string(),
            Err(e) => {
                return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                    system::errors::SystemErrorType::ErrorReadingFile,
                    &e.to_string(),
                )))
            }
        };

        // create the secret path
        let secret_path: String = format!("{}/{}.recs", *DATA, unique_id);

        // Determining chunk amount and size
        let chunk_count: usize = file_size as usize / buffer_size;
        // make a hash
        let full_file_hash: String = create_hash(&filename);

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
        let cipher_data_map = match encrypt(pretty_data_map, fetch_chunk_helper(1), 1024) {
            // ! system files like keys and maps are set to 1024 for buffer to make reading simple
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        // this reads the entire file into a buffer
        // TODO Stream this data with the buffer functions we have already
        let mut file = match File::open(filename) {
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
            Ok(_) => (),
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                append_log(
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
                        signature_count.to_string().len(),
                        VERSION,
                        truncate(&create_hash(&encoded_buffer), 20),
                        signature_count
                    );

                    // hexing all the data for handeling
                    let signature: String = hex::encode(sig_data);
                    // * Running the actual encryption
                    let secret_buffer = match encrypt(
                        encoded_buffer.as_bytes().to_vec(),
                        match create_writing_key(fetch_chunk_helper(num).to_string()) {
                            // TODO ^ Simplyfy this. It is I/o intensive needed multiple files calls multiple times a second
                            Ok(d) => d,
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

                    match write!(
                        match secret_file.as_mut() {
                            Ok(d) => d,
                            Err(e) =>
                                return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                    RecsErrorType::Error,
                                    &e.to_string()
                                ))),
                        },
                        "{}",
                        processed_chunk
                    ) {
                        Ok(()) => (),
                        Err(e) => {
                            return Err(RecsRecivedErrors::RecsError(RecsError::new_details(
                                RecsErrorType::Error,
                                &e.to_string(),
                            )))
                        }
                    };

                    // * DONE RUN THE NEXT CHUNK */
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // reached end of file
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
                del_dir(&secret_path);
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

        // after everything has been written we can delete the file
        if !SOFT_MOVE_FILES {
            match del_file(&secret_data_struct.file_path) {
                Ok(_) => (),
                Err(e) => return Err(RecsRecivedErrors::SystemError(e)),
            }
        }
        // resolving the key data
        let key_data: String = match create_writing_key(fetch_chunk_helper(num).to_string()) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        return Ok((key_data, chunk_count));
    } else {
        append_log(
            unsafe { &PROGNAME },
            &format!("Warning {} doesn't exist", &filename),
        );
        return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
            SystemErrorType::ErrorOpeningFile,
            &format!("Warning {} doesn't exist", &filename),
        )));
    }
}

pub fn write_raw(data: String) -> Result<(String, usize), RecsRecivedErrors> {
    let dummy_path: &str = "/tmp/dummy.recs";
    let dummy_owner: &str = "owner";
    let dummy_name: &str = "temp";
    // write the data to the file

    // ! making the secret path to append data too
    let dummy_file: File = match File::create(dummy_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                SystemErrorType::ErrorOpeningFile,
                &format!("Couldn't create the temp file"),
            )))
        }
    };

    // writing when made
    dummy_file.write_all(format!("{}", data).as_bytes());

    // encrypting the dummy file
    let results: Result<(String, usize), RecsRecivedErrors> = write(
        dummy_path.to_owned(),
        dummy_owner.to_string(),
        dummy_name.to_string(),
    );

    match results {
        Ok((data, count)) => {
            // got the key now get the cipher data
            let key: String = data;
            // finding the dummy map
            let secret_map_path: String = format!("{}/{}-{}.meta", *META, dummy_owner, dummy_name);
            // let secret_json_existence: bool = Path::new(&secret_map_path).exists();
            // decrypting and reading
            let cipher_map_data = match read_to_string(secret_map_path) {
                Ok(d) => d,
                Err(e) => {
                    return Err(RecsRecivedErrors::SystemError(SystemError::new_details(
                        system::errors::SystemErrorType::ErrorOpeningFile,
                        &e.to_string(),
                    )))
                }
            };
            let secret_map_data = match decrypt(&cipher_map_data, fetch_chunk_helper(1)) {
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
                                "Json data decrypted in write function was garbage: {:?}",
                                &secret_map_data
                            ),
                        )))
                    }
                };
            // pulling info from the map
            // ensure the data is there
            if !is_path(&secret_map.secret_path) {
                append_log(
                    unsafe { &PROGNAME },
                    "THE DATA FILE SPECIFIED DOES NOT EXIST",
                );
                return Err(RecsRecivedErrors::RecsError(RecsError::new(
                    RecsErrorType::Error,
                )));
            }

            // reading and printing the file
            let recs_data: Option<String> = match read_to_string(&secret_map.secret_path) {
                Ok(data) => Some(data.replace("\n", "")),
                Err(_) => None,
            };

            forget(dummy_owner.to_owned(), dummy_name.to_owned());

            (Some(key), recs_data, Some(chunks))
        }
        Err(e) => return Err(e),
    }
}

pub fn read_raw(data: String, key: String, chunks: usize) -> (bool, Option<Vec<u8>>) {
    // Recreating the cipher chunk size
    let secret_size: usize = data.chars().count();
    let secret_divisor: usize = chunks;
    let new_buffer_size: usize = secret_size / secret_divisor;

    // * Defing the initial parameters to start reading from string
    // defining the initial pointer range and sig chunk

    let mut range_start: usize = 0;
    let mut range_end: usize = new_buffer_size as usize;
    let mut signature_count: usize = 1;

    let mut encoded_buffer: String = String::new(); // decrypted hex encoded data
    let mut plain_buffer: Vec<u8> = vec![];
    let mut signature: String = String::new(); // the decoded signature

    // ! reading the chunks
    loop {
        // Setting the pointer and cursors before the read

        // ! handeling the file reading and outputs
        while range_start < data.len() {
            let chunk = &data[range_start..range_end];
            let secret_buffer = match std::str::from_utf8(chunk.as_bytes()) {
                Ok(s) => s.to_owned(),
                Err(_) => panic!("Invalid UTF-8 sequence"),
            };

            // take the first spliiting chunk into signature and cipher data
            let encoded_signature: String = truncate(&secret_buffer, 62).to_string();
            let cipher_buffer: String = secret_buffer[62..].to_string();

            // * decrypting the chunk
            encoded_buffer += &decrypt(cipher_buffer.clone(), key.clone());

            // * handeling decoding the signature
            let signature_data = String::from_utf8(
                hex::decode(encoded_signature).expect("Signature could not be decoded"),
            );

            match signature_data {
                Ok(string) => signature += &string,
                Err(e) => println!("Invalid signature: {}", e),
            }

            // ! After 9 chuncks an HMAC error is thrown because the sig size is not updated
            // !? Verify the signature integrity
            match verify_signature(&encoded_buffer, signature.as_str(), signature_count) {
                true => {
                    // ? unencoding buffer
                    let mut plain_result: Vec<u8> = match hex::decode(&encoded_buffer) {
                        Ok(data) => data,
                        Err(_) => {
                            eprint!("Unable to decode the data");
                            exit(233);
                        }
                    };

                    //? updating the pointers and the buffer
                    plain_buffer.append(&mut plain_result);
                    // ? ranges
                    range_start = range_end.clone();
                    range_end += new_buffer_size as usize;
                    signature_count += 1;
                    // ? buffers
                    // #[allow(unused_assignments)]
                    // plain_result = vec![];
                    encoded_buffer = "".to_string();
                    signature = "".to_string();

                    if range_start >= secret_size {
                        return (true, Some(plain_buffer));
                    }
                }
                false => return (false, None),
            }
        }
    }
}

pub fn read(secret_owner: String, secret_name: String) -> bool {
    // creating the secret json path
    append_log(unsafe { &PROGNAME }, "Decrypting request");
    let secret_map_path = format!("{}/{}-{}.meta", *META, secret_owner, secret_name);

    let secret_json_existence: bool = Path::new(&secret_map_path).exists();
    if secret_json_existence {
        let cipher_map_data = read_to_string(secret_map_path).expect("Couldn't read the map file");
        let secret_map_data = decrypt(cipher_map_data, fetch_chunk_helper(1).to_string());
        let secret_map: SecretDataIndex = serde_json::from_str(&secret_map_data).unwrap();

        // ! Validating that we can mess with this data
        if secret_map.version != VERSION {
            eprintln!("Older version of map data. Fucking around and finding out anyway");
            append_log(
                unsafe { &PROGNAME },
                "Data from and older version of recs attempting to read anyway",
            );
        }

        // ensure the data is there
        if !std::path::Path::new(&secret_map.secret_path).exists() {
            eprintln!("An error occoured check logs");
            append_log(
                unsafe { &PROGNAME },
                "THE DATA FILE SPECIFIED DOES NOT EXIST",
            );
        }

        // generating the secret key for the file
        let writting_key: String =
            create_writing_key(fetch_chunk_helper(secret_map.key).to_string());

        // Create chunk map from sig
        // ! this has to be modified to account for the second end byte
        let secret_size: usize = metadata(secret_map.secret_path.clone())
            .expect("an unknown error occoured")
            .len() as usize;
        let secret_divisor: usize = secret_map.chunk_count as usize;
        let new_buffer_size: usize = secret_size / secret_divisor;

        // Defing the loop to read the encrypted file
        let mut file = File::open(secret_map.secret_path.clone()).unwrap();
        // defining the initial pointer range and sig chunk
        let mut buffer: Vec<u8> = vec![0; new_buffer_size];

        let mut range_start: u64 = 0;
        let mut range_end: u64 = new_buffer_size as u64;
        let mut signature_count: usize = 1;

        // ! defing buffer and data that can leave loops
        let mut encoded_buffer: String = String::new(); // decrypted hex encoded data
        let mut signature: String = String::new(); // the decoded signature

        // * checking if its safe to make the file
        let is_file: bool = std::path::Path::new(&secret_map.file_path).exists();
        if is_file == true {
            eprintln!("An error occoured but a good one, check logs");
            append_log(unsafe { &PROGNAME }, "The file requested already exists");
            exit(0);
        }

        let mut plain_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(&secret_map.file_path)
            .expect("Could not create the new file");

        // ! reading the chunks
        loop {
            // Setting the pointer and cursors before the read
            file.seek(SeekFrom::Start(range_start as u64))
                .expect("Failed to set seek head");

            // ! handeling the file reading and outputs
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    let secret_buffer = match std::str::from_utf8(&buffer) {
                        Ok(s) => s.to_owned(),
                        Err(_) => panic!("Invalid UTF-8 sequence"),
                    };

                    // take the first spliiting chunk into signature and cipher data
                    let encoded_signature: String = truncate(&secret_buffer, 62).to_string();
                    let cipher_buffer: String = secret_buffer[62..].to_string();

                    // * decrypting the chunk
                    encoded_buffer += &decrypt(cipher_buffer.clone(), writting_key.clone());

                    // * handeling decoding the signature
                    let signature_data = String::from_utf8(
                        hex::decode(encoded_signature).expect("Signature could not be decoded"),
                    );

                    match signature_data {
                        Ok(string) => signature += &string,
                        Err(e) => println!("Invalid signature: {}", e),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => {
                    eprintln!("An error has occoured check logs");
                    append_log(unsafe { &PROGNAME }, &e.to_string());
                }
            }

            // ! After 9 chuncks an HMAC error is thrown because the sig size is not updated
            // !? Verify the signature integrity // let _sig_digit_count = truncate(&signature, 1);
            match verify_signature(&encoded_buffer, signature.as_str(), signature_count) {
                true => {
                    // ? unencoding buffer
                    let plain_result: Vec<u8> = match hex::decode(&encoded_buffer) {
                        Ok(data) => data,
                        Err(_) => {
                            eprint!("Unable to decode the data");
                            exit(233);
                        }
                    };

                    // ? appending on decode
                    match plain_file.write_all(&plain_result) {
                        Ok(_) => (),
                        Err(_) => panic!("Error while writing to file"),
                    }

                    //? updating the pointers and the buffer
                    range_start = range_end.clone();
                    range_end += new_buffer_size as u64;
                    signature_count += 1;
                    encoded_buffer = "".to_string();
                    signature = "".to_string();
                }
                false => return false,
            }
        }

        return true;
    } else {
        eprintln!("The map requested can't be found");
        append_log(unsafe { &PROGNAME }, "The secret map doen't exist");
        return false;
    }
}

pub fn forget(secret_owner: String, secret_name: String) -> bool {
    // creating the secret json file
    append_log(unsafe { &PROGNAME }, "Forgetting secret");
    let secret_map_path = format!("{}/{}-{}.meta", *META, secret_owner, secret_name);

    // testing if the secret json exists before starting encryption
    if is_path(&secret_map_path) {
        let cipher_map_data =
            read_to_string(secret_map_path.clone()).expect("Couldn't read the json file");
        let secret_map_data = decrypt(cipher_map_data, fetch_chunk_helper(1).to_string());
        let secret_map: SecretDataIndex = serde_json::from_str(&secret_map_data).unwrap();
        // the config
        if LEAVE_IN_PEACE {
            read(secret_owner, secret_name);

            // deleted secret data
            if is_path(&secret_map.secret_path) {
                del_file(&secret_map.secret_path);
            }
            del_file(&secret_map_path);
        } else {
            // deleted secret data
            if is_path(&secret_map.secret_path) {
                del_file(&secret_map.secret_path);
            }
            del_file(&secret_map_path);
        }
        return true;
    } else {
        return false;
    }
}

// * helper funtion for fetching chunks
fn fetch_chunk_helper(num: u32) -> String {
    let chunk_data: Option<String> = match fetch_chunk(num) {
        Some(data) => Some(data),
        None => None,
    };

    if chunk_data == None {
        halt(&format!("Failed to fetch chunk data for number 1"));
    };

    chunk_data.unwrap()
}

fn verify_signature(encoded_buffer: &str, signature: &str, signature_count: usize) -> bool {
    let _sig_digit_count = truncate(&signature, 1); // remember it exists

    let sig_version = truncate(&signature[2..], 6);
    if sig_version != VERSION {
        eprintln!("An error occoured while reading data, check logs");
        append_log( unsafe { &PROGNAME }, "The signature data indicates an older version of recs or encore was used to write this.");
        append_log( unsafe { &PROGNAME }, "I'll try to read this data but if a can't, get an older version or recs or encore and try again");
    }

    let sig_hash = truncate(&signature[9..], 20);
    if truncate(&create_hash(&encoded_buffer.to_owned()), 20).to_string() != sig_hash {
        eprintln!("Something went really wrong, get some coffee or a drink and check the logs");
        append_log(unsafe { &PROGNAME }, "A chunk had an invalid has signature");
        append_log(
            unsafe { &PROGNAME },
            "an option will be in a cli tool to ignore checks in an emergency",
        );
        return false;
    }

    let sig_count_data = &signature[30..];
    let sig_count = sig_count_data.parse::<usize>().unwrap();
    if sig_count != signature_count {
        append_log( unsafe { &PROGNAME }, "Making note: while decrypting the signature counts are mis-aligned foul-play or bad code");
    }

    return true;
}
