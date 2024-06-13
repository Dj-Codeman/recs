use hex::encode;
use logging::append_log;
use nix::unistd::{chown, Uid};
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use std::{
    fs::{canonicalize, metadata, read_to_string, File, OpenOptions},
    io::{prelude::*, SeekFrom},
};
use system::{
    errors::{
        ErrorArray, ErrorArrayItem, Errors as SE, OkWarning, UnifiedResult as uf, WarningArray,
        WarningArrayItem,
    },
    functions::{create_hash, del_dir, del_file, path_present, truncate},
    types::{ClonePath, PathType},
};

// self and create are user made code
use crate::{
    array::array_arimitics,
    array_tools::fetch_chunk,
    auth::create_writing_key,
    encrypt::{decrypt, encrypt},
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
    mut errors: ErrorArray,
    warnings: WarningArray,
) -> uf<(String, usize)> {
    // String is key data, The u16 is the chunk cound
    //TODO Dep or simplyfy
    let max_buffer_size = calc_buffer();
    let file_size: u64 = match metadata(&filename) {
        Ok(d) => d.len(),
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
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
            let err = ErrorArrayItem::new(
                SE::GeneralError,
                format!(
                    "The buffer requested wont cast to usize?: {}",
                    e.to_string()
                ),
            );
            errors.push(err);
            return uf::new(Err(errors));
        }
    };
    let buffer_size: usize = if fit_buffer <= max_buffer_size {
        fit_buffer
    } else {
        fit_buffer / 2
    };

    let msg = format!("{} '{}'", "Attempting to encrypt", &filename);
    if let Err(err) = append_log(unsafe { PROGNAME }, &msg, errors.clone()).uf_unwrap() {
        err.display(false)
    }

    // warn(&filename.to_string());
    let system_paths: SystemPaths = SystemPaths::new();

    // testing if the file exists
    // let filename_existence: bool = path_present(&filename, errors.clone()).unwrap(); //TODO handle this
    let filename_existence: bool = path_present(
        &PathType::PathBuf(canonicalize(&filename).unwrap()),
        errors.clone(),
    )
    .unwrap(); //TODO handle this

    if filename_existence {
        // creating the encrypted meta data file
        let secret_map_path: PathType = PathType::Content(format!(
            "{}/{}-{}.meta",
            system_paths.META, secret_owner, secret_name
        ));

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
                errors.push(ErrorArrayItem::from(e));
                errors.push(ErrorArrayItem::new(
                    SE::OpeningFile,
                    format!("Error opening the canon path {}", filename),
                ));
                return uf::new(Err(errors));
            }
        };

        // create the secret path
        let secret_path: PathType =
            PathType::Content(format!("{}/{}.recs", system_paths.DATA, unique_id));

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

        if let Err(err) = append_log(
            unsafe { PROGNAME },
            &format!("{:?}", secret_data_struct),
            errors.clone(),
        )
        .uf_unwrap()
        {
            err.display(false)
        }

        // formatting the json data
        let pretty_data_map: Vec<u8> = match serde_json::to_vec_pretty(&secret_data_struct) {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                errors.push(ErrorArrayItem::new(
                    SE::ReadingFile,
                    String::from("Couldn't decode data from map file"),
                ));
                return uf::new(Err(errors));
            }
        };
        let cipher_data_map: String = match encrypt(
            pretty_data_map,
            match fetch_chunk_helper(1, errors.clone(), warnings.clone()).uf_unwrap() {
                Ok(d) => d.into(),
                Err(mut e) => {
                    e.push(ErrorArrayItem::new(
                        SE::OpeningFile,
                        String::from("Error getting chunk data"),
                    ));
                    return uf::new(Err(e));
                }
            },
            1024,
            errors.clone(),
        )
        .uf_unwrap()
        {
            // ! system files like keys and maps are set to 1024 for buffer to make reading simple
            Ok(d) => d,
            Err(mut e) => {
                e.push(ErrorArrayItem::new(
                    SE::OpeningFile,
                    String::from("failed to get cipher data map"),
                ));
                return uf::new(Err(e));
            }
        };

        // TODO Stream this data with the buffer functions we have already
        let mut file = match File::open(&filename) {
            Ok(f) => f,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                errors.push(ErrorArrayItem::new(
                    SE::OpeningFile,
                    format!("Couldn't open the file: {}", filename),
                ));
                return uf::new(Err(errors));
            }
        };

        // defining the initial pointer range and sig chunk
        let mut buffer: Vec<u8> = vec![0; buffer_size];
        let mut encoded_buffer = String::new();
        let mut signature_count: usize = 01;
        let mut range_start: u64 = 0;
        let mut range_end: u64 = buffer_size as u64;

        // ! making the secret path to append data too
        let mut secret_file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(secret_path.clone())
        {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                errors.push(ErrorArrayItem::new(
                    SE::OpeningFile,
                    format!("Failed to open secret file path {}", secret_path),
                ));
                return uf::new(Err(errors));
            }
        };

        // ! reading the chunks
        loop {
            let _range_len = range_end - range_start; // ? maybe store this to make reading simpler
                                                      // Setting the pointer and cursors before the read
            match file.seek(SeekFrom::Start(range_start as u64)) {
                Ok(d) => d,
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
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
                            match fetch_chunk_helper(num, errors.clone(), warnings.clone())
                                .uf_unwrap()
                            {
                                Ok(d) => d,
                                Err(e) => return uf::new(Err(e)),
                            },
                            fixed_key,
                            errors.clone(),
                            warnings.clone(),
                        )
                        .uf_unwrap()
                        {
                            // TODO ^ Simplyfy this. It is I/o intensive needed multiple files calls multiple times a second
                            Ok(d) => d.into(),
                            Err(e) => return uf::new(Err(e)),
                        },
                        buffer_size,
                        errors.clone(),
                    )
                    .uf_unwrap()
                    {
                        Ok(d) => d,
                        Err(e) => return uf::new(Err(e)),
                    };

                    // this is the one var thatll be pushed to file
                    let mut processed_chunk: String = String::new();
                    processed_chunk.push_str(&signature);
                    processed_chunk.push_str(&secret_buffer);
                    println!("Processed chunk {}", processed_chunk);
                    // ! THIS IS WHERE THE FILE IS OPENED

                    match write!(secret_file, "{}", processed_chunk) {
                        Ok(_) => (),
                        Err(e) => {
                            errors.push(ErrorArrayItem::from(e));
                            return uf::new(Err(errors));
                        }
                    };

                    // * DONE RUN THE NEXT CHUNK */
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // reached end of file
                    let _ = append_log(
                        unsafe { PROGNAME },
                        &format!("Finished reading data from {}", &filename),
                        errors.clone(),
                    );
                    break;
                }
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
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

        // TODO ERROR HANDELING
        match secret_map_file {
            Ok(_) => match append_log(
                &unsafe { PROGNAME },
                "new secret map created",
                errors.clone(),
            )
            .uf_unwrap()
            {
                Ok(_) => (),
                Err(e) => return uf::new(Err(e)),
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match del_dir(&secret_path, errors.clone()).uf_unwrap() {
                    Ok(_) => (),
                    Err(e) => return uf::new(Err(e)),
                };
                match append_log( &unsafe { PROGNAME }, "The json associated with this file id already exists. Nothing has been deleted.", errors.clone()).uf_unwrap() {
                    Ok(_) => (),
                    Err(e) => return uf::new(Err(e)),
                };
            }
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        match write!(
            match secret_map_file.as_mut() {
                Ok(d) => d,
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            },
            "{}",
            cipher_data_map
        ) {
            Ok(()) => (),
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        // resolving the key data
        let key_data: String = match create_writing_key(
            match fetch_chunk_helper(num, errors.clone(), warnings.clone()).uf_unwrap() {
                Ok(d) => d,
                Err(e) => return uf::new(Err(e)),
            },
            fixed_key,
            errors.clone(),
            warnings.clone(),
        )
        .uf_unwrap()
        {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };
        return uf::new(Ok((key_data, chunk_count)));
    } else {
        let _ = append_log(
            unsafe { PROGNAME },
            &format!("Warning {} doesn't exist", &filename),
            errors.clone(),
        );
        errors.push(ErrorArrayItem::new(
            SE::OpeningFile,
            format!("The file: {} doesn't exist", &filename),
        ));
        return uf::new(Err(errors));
    }
}

pub fn write_raw(
    data: Vec<u8>,
    mut errors: ErrorArray,
    warnings: WarningArray,
) -> uf<(String, String, usize)> {
    // Key_Data Cipher_Data Chunk_Count
    let dummy_path: PathType = PathType::Str("/tmp/dummy.recs".into());
    let dummy_owner: &str = "owner";
    let dummy_name: &str = "temp";
    // write the data to the file
    let system_paths: SystemPaths = SystemPaths::new();

    // ! making the secret path to append data too
    if let Err(err) = del_file(dummy_path.clone(), errors.clone(), warnings.clone()).uf_unwrap() {
        return uf::new(Err(err));
    };
    let mut dummy_file: File = match File::create(dummy_path.clone_path()) {
        Ok(f) => f,
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    // writing when made
    match dummy_file.write_all(&data) {
        Ok(_) => (),
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    // encrypting the dummy file
    let results: Result<(String, usize), ErrorArray> = write(
        dummy_path,
        dummy_owner.to_string(),
        dummy_name.to_string(),
        true,
        errors.clone(),
        warnings.clone(),
    )
    .uf_unwrap();

    println!("{:#?}", &results);

    match results {
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
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            };
            let key_data: String =
                match fetch_chunk_helper(1, errors.clone(), warnings.clone()).uf_unwrap() {
                    Ok(d) => d,
                    Err(e) => return uf::new(Err(e)),
                };

            let secret_map_data: Vec<u8> =
                match decrypt(&cipher_map_data, &key_data, errors.clone()).uf_unwrap() {
                    Ok(d) => d,
                    Err(e) => return uf::new(Err(e)),
                };
            let secret_map: SecretDataIndex =
                match serde_json::from_str(&String::from_utf8_lossy(&secret_map_data)) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };
            // pulling info from the map
            // ensure the data is there
            match path_present(&secret_map.secret_path, errors.clone()).uf_unwrap() {
                Ok(b) => match b {
                    true => (),
                    false => {
                        let _ = append_log(
                            unsafe { PROGNAME },
                            "THE DATA FILE SPECIFIED DOES NOT EXIST",
                            errors.clone(),
                        );
                        errors.push(ErrorArrayItem::new(
                            SE::GeneralError,
                            format!("The data file doesn't exist"),
                        ));
                        return uf::new(Err(errors));
                    }
                },
                Err(e) => return uf::new(Err(e)),
            }

            // reading and printing the file
            let recs_data: String = match read_to_string(&secret_map.secret_path) {
                Ok(data) => data.replace("\n", ""),
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            };

            match forget(
                dummy_owner.to_owned(),
                dummy_name.to_owned(),
                errors.clone(),
                warnings.clone(),
            )
            .uf_unwrap()
            {
                Ok(_) => (),
                Err(e) => return uf::new(Err(e)),
            };

            return uf::new(Ok((key, recs_data, count)));
        }
        Err(e) => return uf::new(Err(e)),
    }
}

pub fn read_raw(
    data: String,
    key: String,
    chunks: usize,
    mut errors: ErrorArray,
    warnings: WarningArray,
) -> uf<OkWarning<Vec<u8>>> {
    // Recreating the cipher chunk size
    let secret_size: usize = data.chars().count();
    let secret_divisor: usize = chunks;
    let new_buffer_size: usize = secret_size / secret_divisor;

    // * Define the initial parameters to start reading from string
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
            let secret_buffer: String = match std::str::from_utf8(chunk.as_bytes()) {
                // This function is reading the hex data from the file, It SHOULD be a string
                Ok(s) => s.to_owned(),
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            };

            // take the first splitting chunk into signature and cipher data
            let encoded_signature: &str = truncate(&secret_buffer, 64);
            // ! When this inevitably fails, Remember the paddingcount() changes the sig legnth.
            let cipher_buffer: &str = &secret_buffer[64..]; // * this is the encrypted hex encoded bytes

            // * decrypting the chunk
            let mut decrypted_data: Vec<u8> =
                match decrypt(&cipher_buffer, &key, errors.clone()).uf_unwrap() {
                    Ok(d) => d, // TODO find a more efficient way to do this
                    Err(e) => return uf::new(Err(e)),
                };

            encoded_buffer.append(&mut decrypted_data);

            // * handling decoding the signature
            // ? This mess decodes the vec array into a hex encoded string, then reads that into a normal &string

            let signature_utf8: Result<String, std::string::FromUtf8Error> =
                String::from_utf8(match hex::decode(encoded_signature) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                });

            let signature_data: String = match signature_utf8 {
                Ok(d) => d,
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            };

            signature += &signature_data;

            // ! After 9 chucks an HMAC error is thrown because the sig size is not updated
            // ! ^ This should be remedied
            // !? Verify the signature integrity
            match verify_signature(
                &encoded_buffer,
                signature.as_str(),
                signature_count,
                warnings.clone(),
                errors.clone(),
            )
            .uf_unwrap()
            {
                Ok(w) => {
                    // * This is where the decoded bytes are retrived
                    let mut plain_result: Vec<u8> = match hex::decode(encoded_buffer.clone()) {
                        Ok(d) => d,
                        Err(e) => {
                            errors.push(ErrorArrayItem::from(e));
                            return uf::new(Err(errors));
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
                        true => {
                            return uf::new(Ok(OkWarning {
                                data: plain_buffer,
                                warning: w.warning,
                            }))
                        }
                        false => (),
                    }
                }
                Err(e) => return uf::new(Err(e)),
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
    mut errors: ErrorArray,
    mut warnings: WarningArray,
) -> uf<OkWarning<(PathType, PathType)>> {
    // creating the secret json path
    match append_log(unsafe { PROGNAME }, "Decrypting request", errors.clone()).uf_unwrap() {
        Ok(_) => (),
        Err(e) => return uf::new(Err(e)),
    };
    let system_paths: SystemPaths = SystemPaths::new();
    let secret_map_path: PathType = PathType::Content(format!(
        "{}/{}-{}.meta",
        system_paths.META, secret_owner, secret_name
    ));

    let secret_json_existence: bool = secret_map_path.to_path_buf().exists();
    if secret_json_existence {
        let cipher_map_data: String =
            read_to_string(secret_map_path).expect("Couldn't read the map file");
        let key_data: String =
            match fetch_chunk_helper(1, errors.clone(), warnings.clone()).uf_unwrap() {
                Ok(d) => d,
                Err(e) => return uf::new(Err(e)),
            };

        let secret_map_data = match decrypt(&cipher_map_data, &key_data, errors.clone()).uf_unwrap()
        {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };
        let secret_map: SecretDataIndex = match serde_json::from_slice(&secret_map_data) {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        let _ = match unsafe { DEBUGGING } {
            Some(bug) => match bug {
                true => append_log(
                    unsafe { PROGNAME },
                    &format!("{:?}", secret_map,),
                    errors.clone(),
                ),
                false => append_log(
                    unsafe { PROGNAME },
                    &format!("Secret map data recived"),
                    errors.clone(),
                ),
            },
            None => append_log(
                unsafe { PROGNAME },
                &format!("Secret map data recived"),
                errors.clone(),
            ),
        };

        if secret_map.version != VERSION {
            warnings.push(WarningArrayItem::new_details(
                system::errors::Warnings::Warning,
                "Signature hash doesn't align".to_string(),
            ))
        }

        // Creating a temp filename to write the data too so we can change the owner and
        // ensure the data is there
        let temp_name: String =
            match path_present(&secret_map.secret_path, errors.clone()).uf_unwrap() {
                Ok(b) => match b {
                    // This ensure the tmp path are more likely to be unique
                    true => truncate(&create_hash(secret_map.secret_path.to_string())[5..], 10)
                        .to_owned(),
                    false => {
                        errors.push(ErrorArrayItem::new(
                            SE::InvalidFile,
                            "secret map path not found".to_string(),
                        ));
                        return uf::new(Err(errors));
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
        match del_file(tmp_path.clone_path(), errors.clone(), warnings.clone()).uf_unwrap() {
            Ok(_) => (),
            Err(e) => return uf::new(Err(e)),
        };

        // generating the secret key for the file
        let writting_key: String = match create_writing_key(
            match fetch_chunk_helper(secret_map.key, errors.clone(), warnings.clone()).uf_unwrap() {
                Ok(d) => d,
                Err(e) => return uf::new(Err(e)),
            },
            fixed_key,
            errors.clone(),
            warnings.clone(),
        )
        .uf_unwrap()
        {
            Ok(d) => d,
            Err(e) => return uf::new(Err(e)),
        };

        // Create chunk map from sig
        // ! this has to be modified to account for the second end byte
        let secret_size: usize = match metadata(&secret_map.secret_path) {
            Ok(d) => {
                if d.len() as usize == 0 {
                    let _ = append_log(
                        unsafe { PROGNAME },
                        "The secret file has a size of zero, it is corrupted",
                        errors.clone(),
                    );
                    errors.push(ErrorArrayItem::new(
                        SE::GeneralError,
                        "Secret file is goofed up".to_string(),
                    ));
                    return uf::new(Err(errors));
                } else {
                    d.len() as usize
                }
            }
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };
        let secret_divisor: usize = secret_map.chunk_count as usize;
        let new_buffer_size: usize = secret_size / secret_divisor;

        // Defing the loop to read the encrypted file
        let mut file = match File::open(&secret_map.secret_path) {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
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
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        // ! reading the chunks
        loop {
            // Setting the pointer and cursors before the read
            match file.seek(SeekFrom::Start(range_start as u64)) {
                Ok(d) => d,
                Err(e) => {
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            };

            // ! handling the file reading and outputs
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    let secret_buffer = match std::str::from_utf8(&buffer) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            errors.push(ErrorArrayItem::from(e));
                            return uf::new(Err(errors));
                        }
                    };
                    println!("Decrypted chunk {}", secret_buffer);
                    // take the first spliiting chunk into signature and cipher data
                    let encoded_signature: &str = truncate(&secret_buffer, 64); // 61 + how ever big the chunk count is
                    let cipher_buffer: &str = &secret_buffer[64..];

                    // * decrypting the chunk
                    let mut decrypted_data: Vec<u8> =
                        match decrypt(&cipher_buffer, &writting_key, errors.clone()).uf_unwrap() {
                            Ok(d) => d,
                            Err(e) => return uf::new(Err(e)),
                        };

                    encoded_buffer.append(&mut decrypted_data);

                    // * handeling decoding the signature
                    let signature_utf8: Result<String, std::string::FromUtf8Error> =
                        String::from_utf8(match hex::decode(encoded_signature) {
                            Ok(d) => d,
                            Err(e) => {
                                errors.push(ErrorArrayItem::from(e));
                                return uf::new(Err(errors));
                            }
                        });

                    let signature_data: String = match signature_utf8 {
                        Ok(d) => d,
                        Err(e) => {
                            errors.push(ErrorArrayItem::from(e));
                            return uf::new(Err(errors));
                        }
                    };

                    signature += &signature_data
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => {
                    match append_log(unsafe { PROGNAME }, &e.to_string(), errors.clone())
                        .uf_unwrap()
                    {
                        Ok(_) => (),
                        Err(e) => return uf::new(Err(e)),
                    };
                    errors.push(ErrorArrayItem::from(e));
                    return uf::new(Err(errors));
                }
            }

            // ! After 9 chucks an HMAC error is thrown because the sig size is not updated
            // ! ^ This should be remedied
            // !? Verify the signature integrity
            // let _sig_digit_count = truncate(&signature, 1);
            match verify_signature(
                &encoded_buffer,
                signature.as_str(),
                signature_count,
                warnings.clone(),
                errors.clone(),
            )
            .uf_unwrap()
            {
                Ok(w) => {
                    // ? unencoding buffer
                    // * This is where the decoded bytes are retrived
                    let plain_result: Vec<u8> = match hex::decode(encoded_buffer.clone()) {
                        Ok(d) => d,
                        Err(e) => {
                            errors.push(ErrorArrayItem::from(e));
                            return uf::new(Err(errors));
                        }
                    };

                    // ? appending on decode
                    match plain_file.write_all(&plain_result) {
                        Ok(_) => (),
                        Err(e) => {
                            errors.push(ErrorArrayItem::from(e));
                            return uf::new(Err(errors));
                        }
                    }

                    //? updating the pointers and the buffer
                    range_start = range_end.clone();
                    range_end += new_buffer_size as u64;
                    signature_count += 1;
                    encoded_buffer.clear();
                    signature = "".to_string();
                    // ? appending any warning
                    warnings.append(w.warning)
                }
                Err(e) => return uf::new(Err(e)),
            }
        }
        let _ = append_log(
            unsafe { PROGNAME },
            &format!(
                "Decrypting request: {} has been decrypted !",
                &secret_map.file_path
            ),
            errors.clone(),
        );
        // changing file owner
        let safe_path = match canonicalize(&tmp_path) {
            Ok(d) => d,
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        };

        match chown(&safe_path, Some(Uid::from_raw(owner_uid)), None) {
            Ok(_) => {
                return uf::new(Ok(OkWarning {
                    data: (tmp_path, secret_map.file_path),
                    warning: warnings,
                }))
            } // return the temporary path and let the client handel it
            Err(e) => {
                errors.push(ErrorArrayItem::from(e));
                return uf::new(Err(errors));
            }
        }
        // moving to the right dir
        // secret_map.file_path
    } else {
        let _ = append_log(
            unsafe { PROGNAME },
            "The secret map doen't exist",
            errors.clone(),
        );
        errors.push(ErrorArrayItem::new(
            SE::InvalidMapData,
            "Secret map not found".to_string(),
        ));
        return uf::new(Err(errors));
    }
}

pub fn forget(
    secret_owner: String,
    secret_name: String,
    mut errors: ErrorArray,
    warnings: WarningArray,
) -> uf<()> {
    // creating the secret json file
    let _ = append_log(unsafe { PROGNAME }, "Forgetting secret", errors.clone());
    let system_paths: SystemPaths = SystemPaths::new();
    let secret_map_path = PathType::Content(format!(
        "{}/{}-{}.meta",
        system_paths.META, secret_owner, secret_name
    ));

    // testing if the secret json exists before starting encryption
    match path_present(&secret_map_path, errors.clone()).uf_unwrap() {
        Ok(d) => match d {
            true => {
                let cipher_map_data: String = match read_to_string(&secret_map_path) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };

                let key_data: String =
                    match fetch_chunk_helper(1, errors.clone(), warnings.clone()).uf_unwrap() {
                        Ok(d) => d,
                        Err(e) => return uf::new(Err(e)),
                    };

                let secret_map_data =
                    match decrypt(&cipher_map_data, &key_data, errors.clone()).uf_unwrap() {
                        Ok(d) => d,
                        Err(e) => return uf::new(Err(e)),
                    };

                let secret_map: SecretDataIndex = match serde_json::from_slice(&secret_map_data) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(ErrorArrayItem::from(e));
                        return uf::new(Err(errors));
                    }
                };

                match path_present(&secret_map.secret_path, errors.clone()).uf_unwrap() {
                    Ok(_) => (),
                    Err(e) => return uf::new(Err(e)),
                }

                match del_file(secret_map_path.clone_path(), errors.clone(), warnings).uf_unwrap() {
                    Ok(_) => {
                        let _ = append_log(
                            unsafe { PROGNAME },
                            &format!("{} has been deleted", &secret_map_path),
                            errors.clone(),
                        );
                    }
                    Err(e) => return uf::new(Err(e)),
                }

                return uf::new(Ok(()));
            }
            false => {
                match append_log(
                    unsafe { PROGNAME },
                    "The file requested doesn't exist",
                    errors.clone(),
                )
                .uf_unwrap()
                {
                    Ok(_) => (),
                    Err(e) => errors.append(e),
                };
                errors.push(ErrorArrayItem::new(
                    SE::GeneralError,
                    format!("The requested file doesn't exist"),
                ));
                return uf::new(Err(errors));
            }
        },
        Err(e) => return uf::new(Err(e)),
    }

    // errors.push(ErrorArrayItem::from(e));
    // return uf::new(Err(errors));
}

// * helper funtion for fetching chunks
fn fetch_chunk_helper(num: u32, errors: ErrorArray, warnings: WarningArray) -> uf<String> {
    match fetch_chunk(num, errors, warnings).uf_unwrap() {
        Ok(d) => return uf::new(Ok(d)),
        Err(e) => return uf::new(Err(e)),
    }
}

fn verify_signature(
    encoded_buffer: &Vec<u8>,
    signature: &str,
    signature_count: usize,
    mut warnings: WarningArray,
    mut errors: ErrorArray,
) -> uf<OkWarning<()>> {
    let _sig_digit_count = truncate(&signature, 1); // remember it exists

    let sig_version = truncate(&signature[3..], 6);

    if sig_version != VERSION {
        warnings.push(WarningArrayItem::new(
            system::errors::Warnings::OutdatedVersion,
        ));
    }

    let new_hash_data: String = match String::from_utf8(encoded_buffer.to_vec()) {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    // pulling the hash from the signature
    let sig_hash: String = truncate(&signature[10..], 20).to_owned();
    let new_hash: String = truncate(&create_hash(new_hash_data.clone()), 20).to_owned();

    if sig_hash != new_hash {
        warnings.push(WarningArrayItem::new_details(
            system::errors::Warnings::Warning,
            "Signature hash doesn't align".to_string(),
        ))
    }

    let sig_count = match signature[31..].parse::<usize>() {
        Ok(d) => d,
        Err(e) => {
            errors.push(ErrorArrayItem::from(e));
            return uf::new(Err(errors));
        }
    };

    if sig_count != signature_count {
        warnings.push(WarningArrayItem::new(
            system::errors::Warnings::MisAlignedChunk,
        ));
    }

    let _ = append_log(
        unsafe { PROGNAME },
        &format!(
            "Decrypting request: {} signatures verified, writing",
            &new_hash
        ),
        errors.clone(),
    );

    return uf::new(Ok(OkWarning {
        data: (),
        warning: warnings,
    }));
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
