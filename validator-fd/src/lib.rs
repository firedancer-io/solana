use std::ffi::{CStr, OsString};
use std::os::unix::ffi::OsStringExt;

#[no_mangle]
pub extern "C" fn solana_validator_main(argv: *const *const i8) {
    let mut args = vec![];

    let mut index = 0;
    unsafe {
        while !(*argv.offset(index)).is_null() {
            args.push(OsString::from_vec(CStr::from_ptr(*argv.offset(index)).to_bytes().to_vec()));

            index += 1;
        }
    }

    solana_validator::main1::main(args.into_iter().map(OsString::from));
}

#[no_mangle]
pub extern "C" fn solana_genesis_main(argv: *const *const i8) {
    let mut args = vec![];

    let mut index = 0;
    unsafe {
        while !(*argv.offset(index)).is_null() {
            args.push(OsString::from_vec(CStr::from_ptr(*argv.offset(index)).to_bytes().to_vec()));

            index += 1;
        }
    }

    solana_genesis::main1::main(args.into_iter().map(OsString::from)).unwrap();
}
