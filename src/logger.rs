use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Fatal => write!(f, "FATAL"),
        }
    }
}

static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);
static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static MIN_LEVEL: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(LogLevel::Info as u8);

/// Generate an ISO 8601-style UTC timestamp string with milliseconds.
pub fn timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();

    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    let days = secs / 86400;
    let mut year = 1970;
    let mut day_count = days;
    loop {
        let leap = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
            1
        } else {
            0
        };
        let days_in_year = 365 + leap;
        if day_count < days_in_year {
            let days_in_months = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            for (month, &dim) in (1..).zip(days_in_months.iter()) {
                if day_count < dim {
                    return format!(
                        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
                        year,
                        month,
                        day_count + 1,
                        hours,
                        minutes,
                        seconds,
                        millis
                    );
                }
                day_count -= dim;
            }
            return format!(
                "{:04}-12-31 {:02}:{:02}:{:02}.{:03}",
                year, hours, minutes, seconds, millis
            );
        }
        day_count -= days_in_year;
        year += 1;
    }
}

/// Recursively formats an error and all its chained underlying causes.
pub fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut result = format!("--> Error: {}", err);
    let mut current = err.source();
    let mut depth = 1;
    while let Some(cause) = current {
        result.push_str(&format!("\n  --> Caused by [{}]: {}", depth, cause));
        current = cause.source();
        depth += 1;
    }
    result
}

/// Initialize the central logger with an optional log file path and minimum log level.
pub fn init(log_file_path: Option<&str>, level: LogLevel) {
    MIN_LEVEL.store(level as u8, Ordering::SeqCst);
    VERBOSE.store(level == LogLevel::Debug, Ordering::SeqCst);

    if let Some(path_str) = log_file_path {
        let path = Path::new(path_str);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }

        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => {
                let mut guard = LOG_FILE.lock().unwrap();
                *guard = Some(file);
                let mut path_guard = LOG_PATH.lock().unwrap();
                *path_guard = Some(path.to_path_buf());
            }
            Err(e) => {
                eprintln!("[-] Warning: Failed to open log file '{}': {}", path_str, e);
            }
        }
    }

    log(
        LogLevel::Info,
        &format!(
            "WARP-MIN logging initialized. Log level: {}. Log file: {}",
            level,
            get_log_path().unwrap_or_else(|| "None (Console only)".to_string())
        ),
    );
}

/// Get the active log file path if configured.
pub fn get_log_path() -> Option<String> {
    let guard = LOG_PATH.lock().unwrap();
    guard.as_ref().map(|p| p.to_string_lossy().to_string())
}

/// Core logging dispatcher: writes to console and disk log file with timestamp and log level.
pub fn log(level: LogLevel, message: &str) {
    if (level as u8) < MIN_LEVEL.load(Ordering::SeqCst) {
        return;
    }

    let ts = timestamp_now();
    let file_line = format!("[{}] [{}] {}\n", ts, level, message);

    // Write to persistent log file immediately with auto-flush
    if let Ok(mut guard) = LOG_FILE.lock()
        && let Some(ref mut file) = *guard
    {
        let _ = file.write_all(file_line.as_bytes());
        let _ = file.flush();
    }

    // Write to console with appropriate standard stream
    match level {
        LogLevel::Error | LogLevel::Fatal => {
            eprintln!("[{}] [{}] {}", ts, level, message);
        }
        LogLevel::Warn => {
            println!("[{}] [{}] {}", ts, level, message);
        }
        _ => {
            println!("{}", message);
        }
    }
}

/// Helper to log a structured error with context and full underlying error chain.
pub fn log_error(context: &str, err: &(dyn std::error::Error + 'static)) {
    let chain = format_error_chain(err);
    let full_msg = format!("{}\n{}", context, chain);
    log(LogLevel::Error, &full_msg);
}

/// Helper to log a fatal error with context, full error chain, and emergency guidance.
pub fn log_fatal(
    context: &str,
    err: &(dyn std::error::Error + 'static),
    suggested_fix: Option<&str>,
) {
    let chain = format_error_chain(err);
    let fix_msg = if let Some(fix) = suggested_fix {
        format!("\n  --> Suggested Action: {}", fix)
    } else {
        String::new()
    };
    let full_msg = format!("{}\n{}{}", context, chain, fix_msg);
    log(LogLevel::Fatal, &full_msg);
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Info, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Warn, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Error, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Debug, &format!($($arg)*))
    };
}

/// Pauses the console on fatal error if running in an interactive window that would otherwise auto-close.
pub fn pause_if_interactive_console_on_error() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::GetConsoleProcessList;
        let mut pids = [0u32; 2];
        let count = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) };
        if count <= 1 {
            println!(
                "\n[!] Process halted with errors. Detailed log saved to: {}",
                get_log_path().unwrap_or_else(|| "warp-min.log".to_string())
            );
            println!("[!] Press Enter to exit...");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockUnderlyingError;
    impl std::fmt::Display for MockUnderlyingError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "The specified module could not be found. (os error 126)")
        }
    }
    impl std::error::Error for MockUnderlyingError {}

    #[derive(Debug)]
    struct MockRootError(MockUnderlyingError);
    impl std::fmt::Display for MockRootError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Failed to load wintun.dll driver library")
        }
    }
    impl std::error::Error for MockRootError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn test_format_error_chain() {
        let err = MockRootError(MockUnderlyingError);
        let formatted = format_error_chain(&err);
        assert!(formatted.contains("Failed to load wintun.dll driver library"));
        assert!(formatted.contains("Caused by [1]: The specified module could not be found."));
    }

    #[test]
    fn test_timestamp_now_format() {
        let ts = timestamp_now();
        assert!(ts.len() >= 23);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], " ");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
        assert_eq!(&ts[19..20], ".");
    }

    #[test]
    fn test_logger_file_write() {
        let temp_dir = std::env::temp_dir();
        let log_file = temp_dir.join(format!("test_warp_min_logger_{}.log", rand::random::<u32>()));
        let log_str = log_file.to_str().unwrap();

        // 1. Test basic write capability at Debug level
        init(Some(log_str), LogLevel::Debug);
        log(LogLevel::Info, "Testing logger disk write capability");
        log(LogLevel::Warn, "Testing warning entry");

        let content = std::fs::read_to_string(&log_file).unwrap();
        assert!(content.contains("Testing logger disk write capability"));
        assert!(content.contains("Testing warning entry"));

        let _ = std::fs::remove_file(&log_file);

        // 2. Test level filtering at Warn level
        let log_file_filter = temp_dir.join(format!("test_warp_min_filter_{}.log", rand::random::<u32>()));
        let log_filter_str = log_file_filter.to_str().unwrap();

        init(Some(log_filter_str), LogLevel::Warn);
        log(LogLevel::Debug, "Debug message should be filtered");
        log(LogLevel::Info, "Info message should be filtered");
        log(LogLevel::Warn, "Warn message should appear");
        log(LogLevel::Error, "Error message should appear");

        let content_filtered = std::fs::read_to_string(&log_file_filter).unwrap();
        assert!(!content_filtered.contains("Debug message should be filtered"));
        assert!(!content_filtered.contains("Info message should be filtered"));
        assert!(content_filtered.contains("Warn message should appear"));
        assert!(content_filtered.contains("Error message should appear"));

        let _ = std::fs::remove_file(&log_file_filter);
    }
}
