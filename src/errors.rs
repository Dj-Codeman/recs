#![allow(deprecated)]

use logging::errors::{LoggerError, MyErrors};
use pretty::output;
use std::fmt;
use system::errors_dep::SystemError;

#[derive(Debug)]
pub enum RecsRecivedErrors {
    LoggerError(LoggerError),
    SystemError(SystemError),
    RecsError(RecsError),
}

pub enum RecsRecivedWarnings {
    RecsWarning(RecsWarning),
}

impl RecsRecivedErrors {
    // This function will take other error classes created by others libs and format them in a easy way
    // to be displayed and handeled by recs
    pub fn repack(errors: MyErrors) -> RecsRecivedErrors {
        match errors {
            MyErrors::LoggerError(logger_error) => {
                return RecsRecivedErrors::LoggerError(logger_error)
            }
            MyErrors::SystemError(system_error) => {
                return RecsRecivedErrors::SystemError(system_error)
            }
        }
    }

    pub fn display(errors: Self, warn: bool) {
        match errors {
            RecsRecivedErrors::LoggerError(d) => match warn {
                true => match d.details {
                    Some(info) => {
                        output("YELLOW", &info);
                    }
                    None => output("YELLOW", &format!("{}", d)),
                },
                false => match d.details {
                    Some(info) => {
                        output("RED", &info);
                    }
                    None => output("RED", &format!("{}", d)),
                },
            },
            RecsRecivedErrors::SystemError(d) => match warn {
                true => match d.details {
                    Some(info) => {
                        output("YELLOW", &info);
                    }
                    None => output("YELLOW", &format!("{}", d)),
                },
                false => match d.details {
                    Some(info) => {
                        output("RED", &info);
                    }
                    None => output("RED", &format!("{}", d)),
                },
            },
            RecsRecivedErrors::RecsError(d) => match warn {
                true => match d.details {
                    Some(info) => {
                        output("YELLOW", &info);
                    }
                    None => output("YELLOW", &format!("{}", d)),
                },
                false => match d.details {
                    Some(info) => {
                        output("RED", &info);
                    }
                    None => output("RED", &format!("{}", d)),
                },
            },
        };
    }
}

// pub fn error_display(warn: bool, error: MyErrors) {
//     // Handeles all types of custom errors passed to it. They will display to the sdin I think
// }

#[derive(Debug, Clone)]
pub struct RecsError {
    pub kind: RecsErrorType,
    pub details: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecsWarning {
    pub kind: RecsWarningType,
    pub details: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RecsErrorType {
    Error,
    InitializationError,
    SecretArrayError,
    JsonCreationError,
    JsonReadingError,
    InvalidTypeGiven,
    InvalidChunkData,
    InvalidHMACData,
    InvalidHMACSize,
    InvalidKey,
    InvalidHexData,
    InvalidIvData,
    InvalidBlockData,
    InvalidAuthRequest,
    InvalidMapRequested,
    InvalidMapVersion,
    InvalidMapData,
    InvalidMapHash,
    InvalidBufferFit,
    InvalidUtf8Data,
    InvalidSignature,
    InvalidFile,
}

#[derive(Debug, Clone)]
pub enum RecsWarningType {
    OutdatedVersion,
    MisAlignedChunk,
    FileNotDeleted,
}

// pretty display
impl fmt::Display for RecsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.details {
            Some(d) => write!(f, "Recs Error: {} - {}", self.kind_description(), d),
            None => write!(f, "Recs Error: {}", self.kind_description()),
        }
    }
}

impl fmt::Display for RecsWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.details {
            Some(d) => write!(f, "Recs Warning: {} - {}", self.kind_description(), d),
            None => write!(f, "Recs Warning: {}", self.kind_description()),
        }
    }
}

impl RecsError {
    pub fn new(kind: RecsErrorType) -> Self {
        RecsError {
            kind,
            details: None,
        }
    }

    pub fn new_details(kind: RecsErrorType, details: &str) -> Self {
        RecsError {
            kind,
            details: Some(details.to_string()),
        }
    }

    fn kind_description(&self) -> String {
        match &self.kind {
            RecsErrorType::Error => String::from("An error occoured please check logs"),
            RecsErrorType::InitializationError => String::from("An error occoured initalizing recs check logs for more info"),
            RecsErrorType::SecretArrayError => String::from("An error occoured while working with the Key array"),
            RecsErrorType::JsonCreationError => String::from("An error occoured while creating json data"),
            RecsErrorType::JsonReadingError => String::from("An error occoured while creating json data"),
            RecsErrorType::InvalidTypeGiven => String::from("A function returned or recived and unexpected type"),
            RecsErrorType::InvalidChunkData => String::from("The encrypted data given is malformed, or I just can't read it"),
            RecsErrorType::InvalidHMACData => String::from("THE INTEGRITY OF THE REQUESTED FILE CAN'T BE VERIFIED. AN INVALID MAC WAS PROVIDED"),
            RecsErrorType::InvalidHMACSize => String::from("FAIL SAFE, somehow I generated an hmac that was longer that 64 bytes. I'm sick"),
            // RecsErrorType::InvalidHexData => String::from("Invalid hex data was provided somewhere while encryping / decrypting"),
            RecsErrorType::InvalidIvData => String::from("Invalid Initial Vector data was provided somewhere while encryping / decrypting"),
            RecsErrorType::InvalidBlockData => String::from("A block mode error has been encountered"),
            RecsErrorType::InvalidAuthRequest => String::from("A userkey request was started with an invalid key"),
            RecsErrorType::InvalidMapRequested => String::from("The map file requested doesn't exist"),
            RecsErrorType::InvalidMapVersion => String::from("The system maps are out of date. Check logs"),
            RecsErrorType::InvalidMapData => String::from("An error occoured while trying to read map data"),
            RecsErrorType::InvalidMapHash => String::from("An error occoured please check logs"),
            RecsErrorType::InvalidBufferFit => String::from("An error occoured while trying to define the writting buffer"),
            RecsErrorType::InvalidUtf8Data => String::from("An error occoured while de-crypting, data that was expected to be utf8 formatted was not."),
            RecsErrorType::InvalidHexData => String::from("An error occoured while de-crypting, data that was expected to be hex formatted that was not"),
            RecsErrorType::InvalidSignature => String::from("The data given has not passed the integrity test"),
            RecsErrorType::InvalidFile => String::from("The file path specified by the secret map doesn'y exist"),
            RecsErrorType::InvalidKey => String::from("An error occoured while preparing the key for encryption"),
            

        }
    }
}

impl RecsWarning {
    pub fn new(kind: RecsWarningType) -> Self {
        RecsWarning {
            kind,
            details: None,
        }
    }

    pub fn new_details(kind: RecsWarningType, details: &str) -> Self {
        RecsWarning {
            kind,
            details: Some(details.to_string()),
        }
    }

    fn kind_description(&self) -> String {
        match &self.kind {
            RecsWarningType::OutdatedVersion => String::from("The signature data indicates an older version of recs or encore was used to write this."),
            RecsWarningType::MisAlignedChunk => String::from("While decrypting the signature counts are mis-aligned, Check hash of returned data to ensure integrity"),
            RecsWarningType::FileNotDeleted => String::from("Error while deleting a file, most likely safe to ignore"),
        }
    }
}
