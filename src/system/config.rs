// currently for debuging
// the stream buffer will be dynamically assigned at runtime
// if this space is not available on run time exit with "No free resources"
// dynamiclly allocated write should have this functionallity built in too
// 1Mb

pub const STREAMING_BUFFER_SIZE: f64 = 102400.00;

//  leave in peace
//  if you want the destroy function to recover the file before deleting
//  the encrypted copy set this true
//  default = true

#[deprecated(
    since = "1.1.0",
    note = "Data can no longer be saved before being forgotten, we don't have the ability to replace the data where it was originally"
)]
pub const _LEAVE_IN_PEACE: bool = false;

// ARRAY_LEN
// the array_len const is a multiple of the chunk size. It determines how many
// chunks the system has to use for cryptographics functions. The higher the
// size the less likely files are to share a common key.

// pub const ARRAY_LEN: u32 = 80963;
pub const ARRAY_LEN: u32 = 64;

// Will document one day. the underline technology is aes-256-cbc
// alot of weird descions led to this needing to be defined but
// dont change this unless your rewriting half of this progect

pub const CHUNK_SIZE: u32 = 16; //5060
