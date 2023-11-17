
use firedancer_sys::*;
use std::ffi::CStr;

const FD_LOG_NUM_LEVELS: i32 = 5;
// Default filename in case we do not get one
const FD_NOFILE: &str = "NOFILE";
// Default line number in case we do not get one
const FD_NOLINE: u32 = 0;

struct FDLogLine {
    level: i32,
    now: i64,
    file: Box<CStr>,
    line: i32,
    func: Box<CStr>,
    msg: Box<CStr>,
}

impl FDLogLine {
    fn new(level: i32, now: i64, file: Box<CStr>, line: i32, func: Box<CStr>, msg: Box<CStr>) -> Self {
        FDLogLine { level, now, file, line, func, msg }
    }

    fn new_from_record(record: &log::Record) -> Self {
        let now = unsafe { util::fd_log_wallclock() } as i64;
        let level = FDLogLine::get_level(record.metadata().level());
        let file = unsafe { CStr::from_bytes_with_nul_unchecked(record.file().unwrap_or(FD_NOFILE).as_bytes()) }.into();
        let line = record.line().unwrap_or(FD_NOLINE) as i32;
        // Rust does not store the enclosing function, so we use
        // the crate::module naming scheme for the function
        let func = unsafe { CStr::from_bytes_with_nul_unchecked(record.metadata().target().as_bytes()) }.into();
        let msg = unsafe { CStr::from_bytes_with_nul_unchecked(record.args().to_string().as_bytes()) }.into();
        FDLogLine { level, now, file, line, func, msg }
    }

    fn get_level(level: log::Level) -> i32 {
        // Rust env_logger levels are inverted compared to firedancer.
        // Moreover, firedancer has more levels than env_logger. And
        // firedancer level starts at 0. Hence, the mapping is as follows:
        //
        // log::Level::Error = 1 ---> FD_LOG_ERR    = 4
        // log::Level::Warn  = 2 ---> FD_LOG_WARN   = 3
        // log::Level::Info  = 3 ---> FD_LOG_NOTICE = 2
        // log::Level::Debug = 4 ---> FD_LOG_INFO   = 1
        // log::Level::Trace = 5 ---> FD_LOG_DEBUG  = 0
        FD_LOG_NUM_LEVELS - level as i32
    }
}

pub struct FDLoggerShim {}

impl log::Log for FDLoggerShim {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // The rust logger only logs to stderr
        let stderr_level = unsafe { util::fd_log_level_stderr() };
        let level = FDLogLine::get_level(metadata.level());
        // Firedancer log levels are inverted compared to env_logger
        // that is, for example, error > info, as also noted above
        level > stderr_level
    }

    fn log(&self, record: &log::Record) {
        let log_line = FDLogLine::new_from_record(record);
        // We always call fd_log_private_1 since it will not abort
        // similar to the behavior of the rust logger, which does
        // not abort, even on an error.
        unsafe { util::fd_log_private_1(
            log_line.level,
            log_line.now,
            log_line.file.as_ptr(),
            log_line.line,
            log_line.func.as_ptr(),
            log_line.msg.as_ptr()
        ) }
    }

    fn flush(&self) {
        unsafe { util::fd_log_flush() }
    }
}
