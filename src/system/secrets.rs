use dusa_collection_utils::{log, logger::LogLevel, types::{pathtype::PathType, stringy::Stringy}};
#[allow(unused_imports)]
use dusa_collection_utils::{
    errors::{
        ErrorArray, ErrorArrayItem, Errors, OkWarning, UnifiedResult as uf, WarningArray,
        WarningArrayItem, Warnings,
    },
    functions::{create_hash, del_dir, del_file, path_present, truncate},
};
use dusa_collection_utils::{functions::generate_random_string};
use hex::encode;
use nix::unistd::{chown, Uid};
use rand::{
    distributions::{Distribution, Uniform},
    rngs::ThreadRng,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{canonicalize, metadata, read_to_string, File, OpenOptions},
    io::{prelude::*, SeekFrom, Write},
};

// self and create are user made code
use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    auth::create_writing_key,
    encrypt::{decrypt, encrypt},
    local_env::{calc_buffer, SystemPaths, VERSION},
    DEBUGGING,
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
    full_file_hash: Stringy,
}

pub async fn write(
    filename: PathType,
    secret_owner: String,
    secret_name: String,
    fixed_key: bool,
) -> uf<(String, usize)> {
    let max_buffer_size = calc_buffer();
    let file_size: u64 = match metadata(&filename) {
        Ok(d) => d.len(),
        Err(e) => return uf::new(Err(ErrorArrayItem::from(e))),
    };

    // Convert file size to usize safely, handle potential overflow
    let fit_buffer: usize = match file_size.try_into() {
        Ok(d) => d,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };

    // Ensure the buffer size is appropriately assigned without exceeding limits
    let buffer_size: usize = if fit_buffer <= max_buffer_size {
        fit_buffer
    } else {
        max_buffer_size // Use the calculated max buffer size if the file size is too large
    };

    log!(
        LogLevel::Trace,
        "{} '{}'",
        "Attempting to encrypt",
        &filename
    );
    let system_paths: SystemPaths = SystemPaths::read_current().await;

    // testing if the file exists
    let filename_existence: bool = filename.exists();

    if filename_existence {
        // creating the encrypted meta data file
        let secret_map_path: PathType = PathType::Content(format!(
            "{}/{}-{}.meta",
            system_paths.META, secret_owner, secret_name
        ));

        // ? picking a chunk number
        let upper_limit: u32 = array_arimitics();
        let lower_limit: u32 = 1;

        let num: u32 = generate_random_number(lower_limit, upper_limit).await;

        // creating the rest of the struct data
        let unique_id: String =
            truncate(&encode(create_hash(filename.to_string()).to_string()), 20).to_string();

        let canon_path: PathType = match canonicalize(&filename) {
            Ok(d) => PathType::PathBuf(d),
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };

        // create the secret path
        let secret_path: PathType =
            PathType::Content(format!("{}/{}.recs", system_paths.DATA, unique_id));

        // Determining chunk amount and size
        let chunk_count: usize = file_size as usize / buffer_size;

        // make a hash
        let full_file_hash: Stringy = create_hash(filename.to_string());

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
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };
        let cipher_data_map: String = match encrypt(
            pretty_data_map,
            match fetch_chunk_helper(1).await.uf_unwrap() {
                Ok(d) => d.into(),
                Err(e) => {
                    log!(LogLevel::Error, "Errot fetching root chunk");
                    return uf::new(Err(e));
                }
            },
            1024,
        )
        .uf_unwrap()
        {
            // ! system files like keys and maps are set to 1024 for buffer to make reading simple
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };

        // TODO Stream this data with the buffer functions we have already
        let mut file = match File::open(&filename) {
            Ok(f) => f,
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
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
                log!(LogLevel::Trace, "File created: {}", &secret_path);
            }
            Err(ref err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // ! might panic
                log!(LogLevel::Trace, "The file already exists {}", &secret_path);
                // return uf::new(Err(ErrorArrayItem::from(err)));
            }
            Err(err) => {
                return uf::new(Err(ErrorArrayItem::from(err)));
            }
        }

        // ! reading the chunks
        loop {
            let _range_len = range_end - range_start; // ? maybe store this to make reading simpeler
                                                      // Setting the pointer and cursors before the read
            match file.seek(SeekFrom::Start(range_start as u64)) {
                Ok(d) => d,
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
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
                        truncate(&*create_hash(encoded_buffer.clone()), 20),
                        signature_count
                    );

                    // hexing all the data for handling
                    let signature: String = hex::encode(sig_data);
                    // * Running the actual encryption
                    let secret_buffer = match encrypt(
                        encoded_buffer.as_bytes().to_vec(),
                        match create_writing_key(
                            match fetch_chunk_helper(num).await.uf_unwrap() {
                                Ok(d) => d,
                                Err(e) => return uf::new(Err(e)),
                            },
                            fixed_key,
                        )
                        .await
                        .uf_unwrap()
                        {
                            // TODO ^ Simplify this. It is I/o intensive needed multiple files calls multiple times a second
                            Ok(d) => d.into(),
                            Err(e) => {
                                return uf::new(Err(e));
                            }
                        },
                        buffer_size,
                    )
                    .uf_unwrap()
                    {
                        Ok(d) => d,
                        Err(e) => return uf::new(Err(e)),
                    };

                    // this is the one var that'll be pushed to file
                    let mut processed_chunk: String = String::new();
                    processed_chunk.push_str(&signature);
                    processed_chunk.push_str(&secret_buffer);
                    // ! THIS IS WHERE THE FILE IS OPENED

                    let result: Result<(), ErrorArrayItem> = match secret_file.as_mut() {
                        Ok(file) => {
                            write!(file, "{}", processed_chunk).map_err(|e| ErrorArrayItem::from(e))
                        }
                        Err(e) => Err(ErrorArrayItem::from(e)),
                    };

                    if let Err(e) = result {
                        return uf::new(Err(ErrorArrayItem::from(e)));
                    };

                    // * DONE RUN THE NEXT CHUNK */
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // reached end of file
                    log!(LogLevel::Trace, "Finished reading data from {}", &filename);
                    break;
                }
                Err(e) => {
                    log!(LogLevel::Error, "Meme");
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            }

            //? updating the pointers and the sig num
            range_start = range_end.clone();
            range_end += buffer_size as u64;
            signature_count += 1;

            // ! New data would be appended if this isn't reset per chunk read
            encoded_buffer = "".to_string();
        }

        // writing to secret data json file
        let mut secret_map_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(&secret_map_path);

        // TODO ERROR HANDLING
        match secret_map_file {
            Ok(_) => log!(LogLevel::Trace, "New secret map created"),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // ? Was del_dir incase of regression
                if let Err(errors) = secret_path.delete() {
                    log!(LogLevel::Error, "{}", errors);
                };

                log!(LogLevel::Trace, "RECS: The json associated with this file id already exists. Nothing has been deleted.");
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };

        // For testing sake will ignore the unused mut as it was defined as mutable before
        #[allow(unused_mut)]
        // Get a mutable reference to the secret_map_file
        let mut secret_map_file = match secret_map_file.as_mut() {
            Ok(d) => d,
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };

        // Write to the file and handle potential errors
        if let Err(e) = write!(secret_map_file, "{}", cipher_data_map) {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }

        // Fetch the chunk
        let chunk = match fetch_chunk_helper(num).await.uf_unwrap() {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };

        // Create the writing key
        let key_result = create_writing_key(chunk, fixed_key);

        let key_data: String = match key_result.await.uf_unwrap() {
            Ok(d) => d,
            Err(e) => {
                return uf::new(Err(e));
            }
        };

        return uf::new(Ok((key_data, chunk_count)));
    } else {
        log!(LogLevel::Error, "Meme");
        log!(LogLevel::Trace, "RECS: {} doesn't exist", &filename);
        return uf::new(Err(ErrorArrayItem::new(
            Errors::OpeningFile,
            format!("Warning {} doesn't exist", &filename),
        )));
    }
}

pub async fn write_raw(data: Vec<u8>) -> uf<(String, String, usize)> {
    let rand_str = generate_random_string(20).unwrap();
    // write the data to the file
    let system_paths: SystemPaths = SystemPaths::read_current().await;
    // Key_Data Cipher_Data Chunk_Count
    let dummy_path: PathType = PathType::Content(format!(
        "{}/{}.rand",
        system_paths.DATA,
        &rand_str
    ));
    let dummy_owner: &str = "system";
    let dummy_name: &str = &rand_str;
    // house keeping
    // clean_temps().await;

    // ! making the secret path to append data too
    let mut dummy_file: File = match File::create(dummy_path.clone()) {
        Ok(f) => f,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };

    // writing when made
    match dummy_file.write_all(&data) {
        Ok(_) => (),
        Err(e) => {
            let mut errors = ErrorArray::new_container();
            errors.push(ErrorArrayItem::from(e));
            errors.push(ErrorArrayItem::new(
                Errors::GeneralError,
                String::from("Error reading from the dummy file"),
            ));
            errors.clone().display(false);
            return uf::new(Err(errors.pop()));
        }
    };

    // encrypting the dummy file
    let results: uf<(String, usize)> = write(
        dummy_path,
        dummy_owner.to_string(),
        dummy_name.to_string(),
        true,
    )
    .await;

    match results.uf_unwrap() {
        Ok((data, count)) => {
            // got the key now get the cipher data
            let key: String = data;
            // finding the dummy map
            let secret_map_path: PathType = PathType::Content(format!(
                "{}/{}-{}.meta",
                system_paths.META, dummy_owner, dummy_name
            ));
            // decrypting and reading
            let cipher_map_data: String = match read_to_string(secret_map_path) {
                Ok(d) => d,
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            };
            let key_data: String = match fetch_chunk_helper(1).await.uf_unwrap() {
                Ok(d) => d,
                Err(e) => {
                    return uf::new(Err(e));
                }
            };

            let secret_map_data: Vec<u8> = match decrypt((&cipher_map_data).into(), &key_data).uf_unwrap() {
                Ok(d) => d,
                Err(e) => {
                    return uf::new(Err(e));
                }
            };
            let secret_map: SecretDataIndex =
                match serde_json::from_str(&String::from_utf8_lossy(&secret_map_data)) {
                    Ok(d) => d,
                    Err(e) => {
                        return uf::new(Err(ErrorArrayItem::from(e)));
                    }
                };
            // pulling info from the map
            // ensure the data is there
            match path_present(&secret_map.secret_path).uf_unwrap() {
                Ok(b) => match b {
                    true => (),
                    false => {
                        log!(
                            LogLevel::Error,
                            "The data file specified doesn't exist: {}",
                            &secret_map.secret_path
                        );
                        return uf::new(Err(ErrorArrayItem::new(
                            Errors::GeneralError,
                            String::from("The data file specified isn't real"),
                        )));
                    }
                },
                Err(e) => return uf::new(Err(e)),
            }

            // reading and printing the file
            let recs_data: String = match read_to_string(&secret_map.secret_path) {
                Ok(data) => data.replace("\n", ""),
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            };

            if let Err(err) = forget(dummy_owner.to_owned(), dummy_name.to_owned()).await {
                return uf::new(Err(err));
            };

            return uf::new(Ok((key, recs_data, count)));
        }
        Err(e) => {
            return uf::new(Err(e));
        }
    }
}

pub fn read_raw(data: String, key: String, chunks: usize) -> uf<Vec<u8>> {
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

        // ! handling the file reading and outputs
        while range_start < data.len() {
            let chunk: &str = &data[range_start..range_end];
            let mut secret_buffer: String = match std::str::from_utf8(chunk.as_bytes()) {
                // This function is reading the hex data from the file, It SHOULD be a string
                Ok(s) => s.to_owned(),
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            };

            // take the first splinting chunk into signature and cipher data
            let encoded_signature: &str = &truncate(&secret_buffer, 62);
            // ! When this inevitably fails, Remember the paddingcount() changes the sig length.
            let cipher_buffer: Stringy = Stringy::from(&*&mut secret_buffer[62..]); // * this is the encrypted hex encoded bytes

            // * decrypting the chunk
            let mut decrypted_data: Vec<u8> = match decrypt(cipher_buffer, &key).uf_unwrap() {
                Ok(d) => d, // TODO find a more efficient way to do this
                Err(e) => return uf::new(Err(e)),
            };

            encoded_buffer.append(&mut decrypted_data);

            // * handling decoding the signature
            // ? This mess decodes the vec array into a hex encoded string, then reads that into a normal &string

            let signature_data: String = match hex::decode(encoded_signature) {
                Ok(decoded) => match String::from_utf8(decoded) {
                    Ok(utf8_string) => utf8_string,
                    Err(e) => {
                        return uf::new(Err(ErrorArrayItem::from(e)));
                    }
                },
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            };

            signature += &signature_data;

            // ! After 9 chuncks an HMAC error is thrown because the sig size is not updated
            // ! ^ This should be remedied
            // !? Verify the signature integrity
            match verify_signature(&encoded_buffer, signature.as_str(), signature_count).uf_unwrap()
            {
                Ok(_) => {
                    // * This is where the decoded bytes are retrieved
                    let mut plain_result: Vec<u8> = match hex::decode(encoded_buffer.clone()) {
                        Ok(d) => d,
                        Err(e) => {
                            return uf::new(Err(ErrorArrayItem::from(e)));
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
                        true => return uf::new(Ok(plain_buffer)),
                        false => (),
                    }
                }
                Err(e) => return uf::new(Err(e)),
            }
        }
    }
}

/// The read function decrypts the data in a temporary path, It will return The path the the file decrypted, The location of the file when it was encrypted, and a Vec<Options<Warning>> if anything non fatal happend
pub async fn read(
    secret_owner: String,
    secret_name: String,
    owner_uid: u32,
    fixed_key: bool,
) -> uf<OkWarning<(PathType, PathType)>> {
    // creating the secret json path
    log!(LogLevel::Trace, "Received decrypt request");
    let system_paths: SystemPaths = SystemPaths::read_current().await;
    let secret_map_path: PathType = PathType::Content(format!(
        "{}/{}-{}.meta",
        system_paths.META, secret_owner, secret_name
    ));

    let secret_json_existence: bool = secret_map_path.to_path_buf().exists();
    if secret_json_existence {
        let cipher_map_data: String =
            read_to_string(secret_map_path).expect("Couldn't read the map file");
        let key_data: String = match fetch_chunk_helper(1).await.uf_unwrap() {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };

        let secret_map_data = match decrypt((&cipher_map_data).into(), &key_data).uf_unwrap() {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };
        let secret_map: SecretDataIndex = match serde_json::from_slice(&secret_map_data) {
            Ok(d) => d,
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };

        let _ = match unsafe { DEBUGGING } {
            Some(bug) => match bug {
                true => log!(LogLevel::Trace, "{:?}", secret_map),
                false => log!(LogLevel::Trace, "Secret map data received"),
            },
            None => log!(LogLevel::Trace, "Secret map data received"),
        };

        // ! Validating that we can mess with this data
        if secret_map.version != VERSION {
            log!(LogLevel::Trace, "The data is from an older version of recs. I'm going to try to read it regardless, in the future this will be a fatal error with the option to ignore it");
        }

        // Creating a temp filename to write the data too so we can change the owner and
        // ensure the data is there
        let temp_name: Stringy = match path_present(&secret_map.secret_path).uf_unwrap() {
            Ok(b) => match b {
                // This ensure the tmp path are more likely to be unique
                true => {
                    truncate(&create_hash(secret_map.secret_path.to_string())[5..], 10)
                }
                false => {
                    return uf::new(Err(ErrorArrayItem::new(
                        Errors::InvalidFile,
                        format!("This is not valid: {}", secret_map.secret_path),
                    )));
                }
            },
            Err(e) => return uf::new(Err(e)),
        };

        // really dumb way to get random int
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let tmp_path: PathType = PathType::Content(format!(
            "/tmp/dusa_{}{:?}",
            temp_name,
            since_the_epoch.as_secs()
        ));

        if let Err(err) = del_file(&tmp_path.clone()).uf_unwrap() {
            // this is just manipulating the order of the errors
            log!(LogLevel::Error, "{err}");
        };

        // Fetch the chunk for the secret key
        let chunk = match fetch_chunk_helper(secret_map.key).await.uf_unwrap() {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };

        // Generate the writing key for the file
        let writing_key: String = match create_writing_key(chunk, fixed_key).await.uf_unwrap() {
            Ok(d) => d,
            Err(e) => {
                return uf::new(Err(e));
            }
        };

        // Create chunk map from sig
        // ! this has to be modified to account for the second end byte
        let secret_size: usize = match metadata(&secret_map.secret_path) {
            Ok(d) => {
                if d.len() as usize == 0 {
                    log!(
                        LogLevel::Error,
                        "The secret file has a size of zero, it is corrupted"
                    );
                    return uf::new(Err(ErrorArrayItem::new(Errors::GeneralError, String::from("The secret file has a length of 0 it is corrupted or wasn't written to"))));
                } else {
                    d.len() as usize
                }
            }
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };
        let secret_divisor: usize = secret_map.chunk_count as usize;
        let new_buffer_size: usize = secret_size / secret_divisor;

        // Define the loop to read the encrypted file
        let mut file = match File::open(&secret_map.secret_path) {
            Ok(d) => d,
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };
        // defining the initial pointer range and sig chunk
        let mut buffer: Vec<u8> = vec![0; new_buffer_size];

        let mut range_start: u64 = 0;
        let mut range_end: u64 = new_buffer_size as u64;
        let mut signature_count: usize = 1;

        // ! define buffer and data that can leave loops
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
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };

        // ! reading the chunks
        loop {
            // Setting the pointer and cursors before the read
            match file.seek(SeekFrom::Start(range_start as u64)) {
                Ok(d) => d,
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            };

            // ! handeling the file reading and outputs
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    let mut secret_buffer = match std::str::from_utf8(&buffer) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            return uf::new(Err(ErrorArrayItem::from(e)));
                        }
                    };

                    // take the first spliiting chunk into signature and cipher data
                    let encoded_signature: Stringy = truncate(&secret_buffer, 62); // 61 + how ever big the chunk count is
                    let cipher_buffer: Stringy = Stringy::from(&*&mut secret_buffer[62..]);

                    // * decrypting the chunk
                    let mut decrypted_data: Vec<u8> =
                        match decrypt(cipher_buffer, &writing_key).uf_unwrap() {
                            Ok(d) => d,
                            Err(e) => return uf::new(Err(e)),
                        };

                    encoded_buffer.append(&mut decrypted_data);

                    // * handeling decoding the signature
                    let signature_utf8: Result<String, std::string::FromUtf8Error> =
                        String::from_utf8(match hex::decode(encoded_signature.to_string()) {
                            Ok(d) => d,
                            Err(e) => {
                                let mut errors = ErrorArray::new_container();
                                errors.push(ErrorArrayItem::new(
                                    Errors::GeneralError,
                                    String::from("Error while reading the signature"),
                                ));
                                errors.push(ErrorArrayItem::from(e));
                                errors.display(false);
                                return uf::new(Err(ErrorArrayItem::from(e)));
                            }
                        });

                    let signature_data: String = match signature_utf8 {
                        Ok(d) => d,
                        Err(e) => {
                            let mut errors = ErrorArray::new_container();
                            errors.push(ErrorArrayItem::new(
                                Errors::GeneralError,
                                String::from("Error while reading the signature"),
                            ));
                            errors.push(ErrorArrayItem::from(e.clone()));
                            errors.display(false);
                            return uf::new(Err(ErrorArrayItem::from(e)));
                        }
                    };

                    signature += &signature_data
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => {
                    return uf::new(Err(ErrorArrayItem::from(e)));
                }
            }

            // ! After 9 chuncks an HMAC error is thrown because the sig size is not updated
            // ! ^ This should be remedied
            // !? Verify the signature integrity
            // let _sig_digit_count = truncate(&signature, 1);
            match verify_signature(&encoded_buffer, signature.as_str(), signature_count).uf_unwrap()
            {
                Ok(_) => {
                    // ? unencoding buffer
                    // * This is where the decoded bytes are retrieved
                    let plain_result: Vec<u8> = match hex::decode(encoded_buffer.clone()) {
                        Ok(d) => d,
                        Err(e) => {
                            return uf::new(Err(ErrorArrayItem::from(e)));
                        }
                    };

                    // ? appending on decode
                    match plain_file.write_all(&plain_result) {
                        Ok(_) => (),
                        Err(e) => {
                            return uf::new(Err(ErrorArrayItem::from(e)));
                        }
                    }

                    //? updating the pointers and the buffer
                    range_start = range_end.clone();
                    range_end += new_buffer_size as u64;
                    signature_count += 1;
                    encoded_buffer.clear();
                    signature = "".to_string();
                }
                Err(e) => return uf::new(Err(e)),
            }
        }
        log!(
            LogLevel::Trace,
            "Decrypting request: {} has been decrypted !",
            &secret_map.file_path
        );
        // changing file owner
        let safe_path = match canonicalize(&tmp_path) {
            Ok(d) => d,
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        };

        match chown(&safe_path, Some(Uid::from_raw(owner_uid)), None) {
            Ok(_) => {
                return uf::new(Ok(OkWarning {
                    data: (tmp_path, secret_map.file_path),
                    warning: WarningArray::new_container(),
                }))
            } // return the temporary path and let the client handel it
            Err(e) => {
                return uf::new(Err(ErrorArrayItem::from(e)));
            }
        }
        // moving to the right dir
        // secret_map.file_path
    } else {
        return uf::new(Err(ErrorArrayItem::new(
            Errors::InvalidMapData,
            String::from("The secret map does not exist"),
        )));
    }
}

pub async fn forget(secret_owner: String, secret_name: String) -> Result<(), ErrorArrayItem> {
    // Creating the secret JSON file path
    log!(LogLevel::Trace, "Forgetting secret");
    let system_paths: SystemPaths = SystemPaths::read_current().await;
    let secret_map_path = PathType::Content(format!(
        "{}/{}-{}.meta",
        system_paths.META, secret_owner, secret_name
    ));

    // Check if the secret map path exists
    if secret_map_path.exists() {
        // Read the cipher map data
        let cipher_map_data =
            read_to_string(&secret_map_path).map_err(|e| ErrorArrayItem::from(e))?;

        // Fetch the key data
        let key_data = fetch_chunk_helper(1).await.uf_unwrap()?;

        // Decrypt the secret map data
        let secret_map_data = decrypt((&cipher_map_data).into(), &key_data)
            .uf_unwrap()
            .map_err(|e| e)?;

        // Deserialize the secret map
        let secret_map: SecretDataIndex =
            serde_json::from_slice(&secret_map_data).map_err(|e| {
                ErrorArrayItem::new(
                    Errors::GeneralError,
                    format!("Error reading secret data JSON: {}", e),
                )
            })?;

        // Check if the secret path exists and delete it
        if secret_map.secret_path.exists() {
            del_file(&secret_map.secret_path).uf_unwrap()?;
        }

        // Delete the secret map file
        del_file(&secret_map_path.clone()).uf_unwrap()?;
        log!(LogLevel::Trace, "{} has been deleted", &secret_map_path);

        Ok(())
    } else {
        log!(
            LogLevel::Error,
            "The file requested doesn't exist: {}",
            &secret_map_path
        );
        return Err(ErrorArrayItem::new(
            Errors::GeneralError,
            String::from("The file requested doesn't exist"),
        ));
    }
}

// * helper funtion for fetching chunks
async fn fetch_chunk_helper(num: u32) -> uf<String> {
    match fetch_chunk(num).await.uf_unwrap() {
        Ok(d) => return uf::new(Ok(d)),
        Err(e) => return uf::new(Err(e)),
    }
}

fn verify_signature(encoded_buffer: &Vec<u8>, signature: &str, signature_count: usize) -> uf<()> {
    let _sig_digit_count = truncate(&*signature, 2); // remember it exists

    let sig_version = truncate(&signature[3..], 6);

    if sig_version != VERSION.into() {
        log!(LogLevel::Trace, "RECS: The version in the data signature isn't my version. I'll try to read it but it may be incompatible");
        log!(
            LogLevel::Trace,
            "RECS: Current version: {}, Packet version: {}",
            VERSION,
            sig_version
        );
    }

    let new_hash_data: String = match String::from_utf8(encoded_buffer.to_vec()) {
        Ok(d) => d,
        Err(e) => {
            return uf::new(Err(ErrorArrayItem::from(e)));
        }
    };
    // pulling the hash from the signature
    let sig_hash: Stringy = truncate(&signature[10..], 20).to_owned();
    let new_hash: Stringy = truncate(&*create_hash(new_hash_data.clone()), 20).to_owned();

    if sig_hash != new_hash {
        log!(
            LogLevel::Trace,
            "A chunk has an invalid signature, Proceeding anyway",
        );
        log!(
            LogLevel::Trace,
            "In a later version this will be a fatal error with an option to ignore it",
        );
    };

    // TODO change the parsing to read the actual number from the signature
    let sig_count = match signature[30..].parse::<usize>() {
        Ok(d) => d,
        Err(e) => {
            log!(LogLevel::Error, "{}", ErrorArrayItem::from(e));
            1
        }
    };

    if sig_count != signature_count {
        log!(LogLevel::Trace, "The calculated chunk count and the reported chunk count don't align ? continuing anyway -\\:)/- ");
        log!(
            LogLevel::Trace,
            "In a later version this will be a fatal error with an option to ignore it",
        );
    }

    log!(
        LogLevel::Trace,
        "Decrypting request: {} signatures verified, writing",
        &new_hash
    );

    return uf::new(Ok(()));
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

async fn generate_random_number(lower_limit: u32, upper_limit: u32) -> u32 {
    let mut rng: ThreadRng = rand::thread_rng(); // This is `Send`
    let range: Uniform<u32> = Uniform::new(lower_limit, upper_limit);
    let num: u32 = range.sample(&mut rng);
    num
}
