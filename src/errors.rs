use logging::errors::{LoggerError, MyErrors};
use pretty::output;
use std::fmt;
use system::errors::SystemError;

pub enum RecsRecivedErrors {
    LoggerError(LoggerError),
    SystemError(SystemError),
    RecsError(RecsError),
}

impl RecsRecivedErrors {
    // This function will take other error classes created by others libs and format them in a easy way
    // to be displayed and handeled by recs
    pub fn repack(errors: MyErrors) -> RecsRecivedErrors {
        match errors {
            MyErrors::LoggerError(LoggerError) => {
                return RecsRecivedErrors::LoggerError(LoggerError)
            }
            MyErrors::SystemError(SystemError) => {
                return RecsRecivedErrors::SystemError(SystemError)
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

pub fn error_display(warn: bool, error: MyErrors) {
    // Handeles all types of custom errors passed to it. They will display to the sdin I think
}

#[derive(Debug)]
pub struct RecsError {
    pub kind: RecsErrorType,
    pub details: Option<String>,
}

#[derive(Debug)]
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
    InvalidHexData,
    InvalidIvData,
    InvalidBlockData,
    InvalidAuthRequest,
}

// pretty display
impl fmt::Display for RecsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.details {
            Some(d) => write!(f, "Logger Error: {} - {}", self.kind_description(), d),
            None => write!(f, "Logger Error: {}", self.kind_description()),
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
            details: Some(details.to_string())
        }
    }

    fn kind_description(&self) -> String {
        match &self.kind {
            RecsErrorType::Error => String::from("Program name defined is invalid"),
            RecsErrorType::InitializationError => String::from("An error occoured initalizing recs check logs for more info"),
            RecsErrorType::SecretArrayError => String::from("An error occoured while working with the Key array"),
            RecsErrorType::JsonCreationError => String::from("An error occoured while creating json data"),
            RecsErrorType::JsonReadingError => String::from("An error occoured while creating json data"),
            RecsErrorType::InvalidTypeGiven => String::from("A function returned or recived and unexpected type"),
            RecsErrorType::InvalidChunkData => String::from("The encrypted data given is malformed, or I just can't read it"),
            RecsErrorType::InvalidHMACData => String::from("THE INTEGRITY OF THE REQUESTED FILE CAN'T BE VERIFIED. AN INVALID MAC WAS PROVIDED"),
            RecsErrorType::InvalidHMACSize => String::from("FAIL SAFE, somehow I generated an hmac that was longer that 64 bytes. I'm sick"),
            RecsErrorType::InvalidHexData => String::from("Invalid hex data was provided somewhere while encryping / decrypting"),
            RecsErrorType::InvalidIvData => String::from("Invalid Initial Vector data was provided somewhere while encryping / decrypting"),
            RecsErrorType::InvalidBlockData => String::from("A block mode error has been encountered"),
            RecsErrorType::InvalidAuthRequest => String::from("A userkey request was started with an invalid key"),


        }
    }
}