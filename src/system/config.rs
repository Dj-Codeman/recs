
	// DEBUG
	// show in depth stack info on panics

pub const DEBUG: bool = true;


pub const SYSTEM_ARRAY_LOCATION: &str = "/var/recs/array.recs";

	//	The user key is derived from the users specific password
	//	This is the key used to encrypt the files while
	//	the maps will still use the system array
	//  if this key is missing on script call all file in:
	//  $datadir will be illegible
	//  IF THIS KEY IS DELETED ALL DATA IS CONSIDERED LOST

pub const USER_KEY_LOCATION: &str = "/var/recs/userdata.recs";

	// currently for debuging 
	// the stream buffer will be dynamically assigned at runtime
	// if this space is not available on run time exit with "No free resources"
	// dynamiclly allocated write should have this functionallity built in too 
	// 1Mb 

pub const STREAMING_BUFFER_SIZE: f64 = 102400.00;

	//  soft moving
	//  set 1 to use cp instead of mv when gatheing files to encrypt
	//  default = false

pub const SOFT_MOVE_FILES: bool = false;


	//  leave in peace
	//  if you want the destroy function to recover the file before deleting
	//  the encrypted copy set this true
	//  default = true


pub const LEAVE_IN_PEACE: bool = false;

	// ARRAY_LEN 
	// the array_len const is a multiple of the chunk size. It determines how many 
	// chunks the system has to use for cryptographics functions. The higher the
	// size the less likely files are to share a common key.

pub const ARRAY_LEN: u32 = 80963;


	// Will document one day. the underline technology is aes-256-cbc
	// alot of weird descions led to this needing to be defined but 
	// dont change this unless your rewriting half of this progect

pub const CHUNK_SIZE: u32 = 16; //5060