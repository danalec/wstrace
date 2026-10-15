pub mod elevation;
pub mod error_codes;
pub mod etw;
pub mod process_launcher;
pub mod qpc;
pub mod win32_probe;

pub use elevation::{detect_elevation, is_elevated, ElevationLevel};
pub use error_codes::{
    format_result_code, lookup_error_code, lookup_ntstatus, lookup_win32_error, ErrorInfo,
    ErrorSeverity,
};
pub use etw::EtwConsumer;
pub use process_launcher::spawn_target_process;
pub use qpc::{calculate_elapsed_us, read_qpc_ticks};
pub use win32_probe::Win32Probe;
