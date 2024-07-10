use logging::append_log;
use system::errors::ErrorArray;

use crate::PROGNAME;

pub fn log(data: String) {
    let errors: ErrorArray = ErrorArray::new_container();
    #[allow(static_mut_refs)]
    if let Err(e) = append_log(unsafe { &PROGNAME }, &data, errors.clone()).uf_unwrap() {
        e.display(false);
    }
    drop(errors);
    drop(data);
}