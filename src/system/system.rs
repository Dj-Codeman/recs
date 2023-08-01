use chrono::{Datelike, DateTime, Timelike, Local};
use std::{io::Write, fs::OpenOptions, str};
use crate::config::LOG_FILE_LOCATION;

// Defining terminal colors
const COLOR_BLACK:  &str = "\u{001b}[30m"; // Terminals are black why output black ???
const COLOR_RED:    &str = "\u{001b}[31m";
const COLOR_GREEN:  &str = "\u{001b}[32m";
const COLOR_YELLOW: &str = "\u{001b}[33m";
const COLOR_BLUE:   &str = "\u{001b}[34m";
const COLOR_BOLD:   &str = "\x1B[1m";
const COLOR_RESET:  &str = "\u{001b}[0m";

// Defining version number
pub const VERSION: &str = "R1.1.1";

// Defining static content
pub const HELP: &str = "\nencore [--write] encrypt new object [--read] decrypt object [--forget] delete a stored object 
\nencore [--test] system tests (for important builds) [--initialize] recreates keys and deletes data
\nencore [--version] Prints the current version of encore.
\nFor more help try encore --help --write or encore --help --read !!!\n";

pub fn output(color: &str, text: &str) {

    match color {
        "RED" => {
            let color: &str = COLOR_RED;
            print_text(color, &text);
        }
        "GREEN" => {
            let color: &str = COLOR_GREEN;
            print_text(color, &text);
        }
        "YELLOW" => {
            let color: &str = COLOR_YELLOW;
            print_text(color, &text);
        }
        "BLUE" => {
            let color: &str = COLOR_BLUE;
            print_text(color, &text);        
        }
        _ => {
            let color: &str = COLOR_BLACK;
            print_text(color, &text);
        }
    }

    fn print_text(_color: &str, _text: &str) {
        // print!("{}{}{}{}", COLOR_BOLD, color, text, COLOR_RESET);
        // Need to remove refrences

    }
}

pub fn pass(text: &str) {
    println!("{}{}{}! {}", COLOR_BOLD, COLOR_GREEN, text, COLOR_RESET);
    std::process::exit(0);
}

pub fn notice(text: &str) {
    println!("{}{}Notice: {}! {}", COLOR_BOLD, COLOR_BLUE, text, COLOR_RESET);
}

pub fn warn(text: &str) {
    println!("{}{}Warning: {}! {}", COLOR_BOLD, COLOR_YELLOW, text, COLOR_RESET);
}

pub fn halt(text: &str) {
    println!("{}{}Panic!: {}! {}", COLOR_BOLD, COLOR_RED, text, COLOR_RESET);
    std::process::exit(1);
}

// * for debugging only
pub fn _dump(text: &str) {
    println!("{}{}DUMPED: {}! {}", COLOR_BOLD, COLOR_YELLOW, text, COLOR_RESET);
    std::process::exit(13);
}

// ! argument tools
//* getting and counting positional arguments

pub fn min_arguments(min: usize) -> bool {
    // pulling the legnth from the standart env arguments
    let args_len: usize = std::env::args().len() - 1;

    if args_len >= min {
        return true;

    } else {
        return false; 
    }
}

pub fn fetch_arguments() -> Vec<String> {
    let args_array: Vec<_> = std::env::args().collect();
    return args_array;
}

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
        halt("Could not create or write to new log file");
    }

    let msg: String = String::from("Log Created! \n");
    output("GREEN", &msg);
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
        warn("Couldn't open already existing log file");
    }
}

// ! File manipulation
pub fn unexist(path: &str) {
    if std::path::Path::new(path).exists() { // deleting the original one
        std::fs::remove_file(path).unwrap();
    }
}
