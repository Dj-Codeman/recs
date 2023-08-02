use chrono::{Datelike, DateTime, Timelike, Local};
use std::{io::Write, fs::OpenOptions, str, process::exit};
use crate::config::LOG_FILE_LOCATION;

// Defining terminal colors
// const COLOR_YELLOW: &str = "\u{001b}[33m";
// const COLOR_BOLD:   &str = "\x1B[1m";
// const COLOR_RESET:  &str = "\u{001b}[0m";

// Defining version number
pub const VERSION: &str = "R1.0.0";

// Defining static content
// pub const _HELP: &str = "\nencore [--write] encrypt new object [--read] decrypt object [--forget] delete a stored object 
// \nencore [--test] system tests (for important builds) [--initialize] recreates keys and deletes data
// \nencore [--version] Prints the current version of encore.
// \nFor more help try encore --help --write or encore --help --read !!!\n";

// * for debugging only
// pub fn dump(text: &str) {
//     println!("{}{}DUMPED: {}! {}", COLOR_BOLD, COLOR_YELLOW, text, COLOR_RESET);
//     std::process::exit(13);
// }

pub fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}
// ! LOGGING

fn timestamp() -> String {
    // Getting the data 
    let mut timestamp: String = String::new();
    let current_time: DateTime<Local> = Local::now();

    let day: u32 = current_time.day();
    let month: u32 = current_time.month();
    let year: i32 = current_time.year();
    let hour: u32 = current_time.hour();
    let minute: u32 = current_time.minute();
    let second: u32 = current_time.second();

    // adding foward 0 padding to dates
    let year_string: String = year.to_string();

    fn padding_date(number: u32) -> String {
        if number < 10 {
            let mut local_date_string = String::new();
            local_date_string.push_str("0");
            local_date_string.push_str(&number.to_string());
            return local_date_string;
        } else {
            let local_date_string: String = String::from(&number.to_string());
            return local_date_string;
        }
    }

    timestamp.push_str(&year_string);
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(month));
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(day));
    timestamp.push_str("_");
    timestamp.push_str(&padding_date(hour));
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(minute));
    timestamp.push_str("-");
    timestamp.push_str(&padding_date(second));

    return timestamp;
}

pub fn start_log() {
    let mut log_msg: String = String::new();
    log_msg.push_str(" LOG START");
    log_msg.push_str(" @ ");
    log_msg.push_str(&timestamp());
    log_msg.push_str("\n");
    // write to log function

    // if al old log exists delete it
    if std::path::Path::new(LOG_FILE_LOCATION).exists() {
        std::fs::remove_file(LOG_FILE_LOCATION).unwrap();
    }

    let mut log_file = OpenOptions::new()
    .create_new(true)
    .write(true)
    .append(true)
    .open(LOG_FILE_LOCATION)
    .expect("File could not be opened");

    if let Err(_e) = writeln!(log_file, "{}", log_msg) {
        append_log("Could not create or write to new log file");
        exit(1);
    }

}

pub fn append_log(data: &str) {
    // Makign data
    let mut log_msg: String = String::new();
    log_msg.push_str(data);
    log_msg.push_str(" @ ");
    log_msg.push_str(&timestamp());
    log_msg.push_str("\n");

    // Opening the file
    let mut log_file = OpenOptions::new().write(true).append(true).open(LOG_FILE_LOCATION).expect("File could not be opened");

    // Hendeling errs
    if let Err(_e) = writeln!(log_file, "{}", log_msg) {
        eprintln!("Couldn't open already existing log file")
    }
}

// ! File manipulation
pub fn unexist(path: &str) {
    if std::path::Path::new(path).exists() { // deleting the original one
        std::fs::remove_file(path).unwrap();
    }
}

pub fn exist(path: &str) -> bool {
    if std::path::Path::new(path).exists() { 
        return true;
    } else {
        return false;
    }
}