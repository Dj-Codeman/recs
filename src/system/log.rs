use simple_tmp_logger::append_log;
use dusa_collection_utils::errors::ErrorArray;

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
