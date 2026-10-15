// wstrace - Structured NTSTATUS & Win32 Result Codes

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Success,
    Informational,
    Warning,
    Error,
}

impl ErrorSeverity {
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Warning | Self::Error)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Informational => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorInfo {
    pub code: u32,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: ErrorSeverity,
}

/// Resolves a Win32 error code or NTSTATUS code to its structured metadata.
///
/// Note: Code `0` is resolved as `ERROR_SUCCESS` via the Win32 lookup table fallback.
/// When NTSTATUS context is explicitly required, caller should use `lookup_ntstatus(0)`.
pub fn lookup_error_code(code: u32) -> Option<ErrorInfo> {
    // Check NTSTATUS codes first (top 2 bits set or 0xC000xxxx / 0x8000xxxx / 0x4000xxxx)
    if code >= 0x4000_0000 || (0x0000_0100..=0x0000_0105).contains(&code) {
        if let Some(info) = lookup_ntstatus(code) {
            return Some(info);
        }
    }

    lookup_win32_error(code)
}

/// Lookup table for common Win32 API result codes.
pub fn lookup_win32_error(code: u32) -> Option<ErrorInfo> {
    match code {
        0 => Some(ErrorInfo {
            code,
            name: "ERROR_SUCCESS",
            description: "The operation completed successfully.",
            severity: ErrorSeverity::Success,
        }),
        1 => Some(ErrorInfo {
            code,
            name: "ERROR_INVALID_FUNCTION",
            description: "Incorrect function.",
            severity: ErrorSeverity::Error,
        }),
        2 => Some(ErrorInfo {
            code,
            name: "ERROR_FILE_NOT_FOUND",
            description: "The system cannot find the file specified.",
            severity: ErrorSeverity::Error,
        }),
        3 => Some(ErrorInfo {
            code,
            name: "ERROR_PATH_NOT_FOUND",
            description: "The system cannot find the path specified.",
            severity: ErrorSeverity::Error,
        }),
        5 => Some(ErrorInfo {
            code,
            name: "ERROR_ACCESS_DENIED",
            description: "Access is denied.",
            severity: ErrorSeverity::Error,
        }),
        6 => Some(ErrorInfo {
            code,
            name: "ERROR_INVALID_HANDLE",
            description: "The handle is invalid.",
            severity: ErrorSeverity::Error,
        }),
        8 => Some(ErrorInfo {
            code,
            name: "ERROR_NOT_ENOUGH_MEMORY",
            description: "Not enough memory resources are available to process this command.",
            severity: ErrorSeverity::Error,
        }),
        14 => Some(ErrorInfo {
            code,
            name: "ERROR_OUTOFMEMORY",
            description: "Not enough storage is available to complete this operation.",
            severity: ErrorSeverity::Error,
        }),
        32 => Some(ErrorInfo {
            code,
            name: "ERROR_SHARING_VIOLATION",
            description:
                "The process cannot access the file because it is being used by another process.",
            severity: ErrorSeverity::Error,
        }),
        50 => Some(ErrorInfo {
            code,
            name: "ERROR_NOT_SUPPORTED",
            description: "The request is not supported.",
            severity: ErrorSeverity::Error,
        }),
        87 => Some(ErrorInfo {
            code,
            name: "ERROR_INVALID_PARAMETER",
            description: "The parameter is incorrect.",
            severity: ErrorSeverity::Error,
        }),
        123 => Some(ErrorInfo {
            code,
            name: "ERROR_INVALID_NAME",
            description: "The filename, directory name, or volume label syntax is incorrect.",
            severity: ErrorSeverity::Error,
        }),
        183 => Some(ErrorInfo {
            code,
            name: "ERROR_ALREADY_EXISTS",
            description: "Cannot create a file when that file already exists.",
            severity: ErrorSeverity::Warning,
        }),
        259 => Some(ErrorInfo {
            code,
            name: "ERROR_NO_MORE_ITEMS",
            description: "No more data is available or process still active.",
            severity: ErrorSeverity::Informational,
        }),
        997 => Some(ErrorInfo {
            code,
            name: "ERROR_IO_PENDING",
            description: "Overlapped I/O operation is in progress.",
            severity: ErrorSeverity::Informational,
        }),
        1056 => Some(ErrorInfo {
            code,
            name: "ERROR_SERVICE_ALREADY_RUNNING",
            description: "An instance of the service is already running.",
            severity: ErrorSeverity::Warning,
        }),
        1060 => Some(ErrorInfo {
            code,
            name: "ERROR_SERVICE_DOES_NOT_EXIST",
            description: "The specified service does not exist as an installed service.",
            severity: ErrorSeverity::Error,
        }),
        1223 => Some(ErrorInfo {
            code,
            name: "ERROR_CANCELLED",
            description: "The operation was canceled by the user.",
            severity: ErrorSeverity::Warning,
        }),
        _ => None,
    }
}

/// Lookup table for NTSTATUS codes.
pub fn lookup_ntstatus(status: u32) -> Option<ErrorInfo> {
    match status {
        0x0000_0000 => Some(ErrorInfo {
            code: status,
            name: "STATUS_SUCCESS",
            description: "The operation completed successfully.",
            severity: ErrorSeverity::Success,
        }),
        0x0000_0102 => Some(ErrorInfo {
            code: status,
            name: "STATUS_TIMEOUT",
            description: "The operation timed out.",
            severity: ErrorSeverity::Warning,
        }),
        0x0000_0103 => Some(ErrorInfo {
            code: status,
            name: "STATUS_PENDING",
            description: "The operation is pending completion.",
            severity: ErrorSeverity::Informational,
        }),
        0x4000_0000 => Some(ErrorInfo {
            code: status,
            name: "STATUS_OBJECT_NAME_EXISTS",
            description: "The object name already exists.",
            severity: ErrorSeverity::Warning,
        }),
        0x8000_0005 => Some(ErrorInfo {
            code: status,
            name: "STATUS_BUFFER_OVERFLOW",
            description: "The data was too large to fit into the specified buffer.",
            severity: ErrorSeverity::Warning,
        }),
        0x8000_0006 => Some(ErrorInfo {
            code: status,
            name: "STATUS_NO_MORE_FILES",
            description: "No more files were found which match the file specification.",
            severity: ErrorSeverity::Informational,
        }),
        0xC000_0001 => Some(ErrorInfo {
            code: status,
            name: "STATUS_UNSUCCESSFUL",
            description: "The specified request is not a valid operation for the target device.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0005 => Some(ErrorInfo {
            code: status,
            name: "STATUS_ACCESS_VIOLATION",
            description: "The instruction at referenced memory could not be read or written.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0008 => Some(ErrorInfo {
            code: status,
            name: "STATUS_INVALID_HANDLE",
            description: "An invalid handle was specified.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_000D => Some(ErrorInfo {
            code: status,
            name: "STATUS_INVALID_PARAMETER",
            description: "An invalid parameter was passed to a service or function.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_000F => Some(ErrorInfo {
            code: status,
            name: "STATUS_NO_SUCH_FILE",
            description: "The specified file does not exist.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0011 => Some(ErrorInfo {
            code: status,
            name: "STATUS_END_OF_FILE",
            description: "The end-of-file marker has been reached.",
            severity: ErrorSeverity::Informational,
        }),
        0xC000_0022 => Some(ErrorInfo {
            code: status,
            name: "STATUS_ACCESS_DENIED",
            description: "A process has requested access to an object, but has not been granted those access rights.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0023 => Some(ErrorInfo {
            code: status,
            name: "STATUS_BUFFER_TOO_SMALL",
            description: "The buffer is too small to contain the entry.",
            severity: ErrorSeverity::Warning,
        }),
        0xC000_0034 => Some(ErrorInfo {
            code: status,
            name: "STATUS_OBJECT_NAME_NOT_FOUND",
            description: "The object name, path, or file was not found.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0035 => Some(ErrorInfo {
            code: status,
            name: "STATUS_OBJECT_NAME_COLLISION",
            description: "The object name already exists.",
            severity: ErrorSeverity::Warning,
        }),
        0xC000_003A => Some(ErrorInfo {
            code: status,
            name: "STATUS_OBJECT_PATH_NOT_FOUND",
            description: "The path does not exist.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0043 => Some(ErrorInfo {
            code: status,
            name: "STATUS_SHARING_VIOLATION",
            description: "A file cannot be opened because the share options conflict with another open.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0061 => Some(ErrorInfo {
            code: status,
            name: "STATUS_PRIVILEGE_NOT_HELD",
            description: "A required privilege is not held by the client.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_00BA => Some(ErrorInfo {
            code: status,
            name: "STATUS_FILE_IS_A_DIRECTORY",
            description: "The file that was specified as a target is a directory, not a file.",
            severity: ErrorSeverity::Warning,
        }),
        0xC000_010A => Some(ErrorInfo {
            code: status,
            name: "STATUS_PROCESS_IS_TERMINATING",
            description: "An attempt was made to access an exiting process.",
            severity: ErrorSeverity::Warning,
        }),
        0xC000_0135 => Some(ErrorInfo {
            code: status,
            name: "STATUS_DLL_NOT_FOUND",
            description: "The specified dynamic-link library could not be found.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0139 => Some(ErrorInfo {
            code: status,
            name: "STATUS_ENTRYPOINT_NOT_FOUND",
            description: "The specified procedure could not be found in the DLL.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_0142 => Some(ErrorInfo {
            code: status,
            name: "STATUS_DLL_INIT_FAILED",
            description: "The dynamic link library failed initialization.",
            severity: ErrorSeverity::Error,
        }),
        0xC000_042C => Some(ErrorInfo {
            code: status,
            name: "STATUS_ELEVATION_REQUIRED",
            description: "The requested action requires administrative elevation.",
            severity: ErrorSeverity::Error,
        }),
        _ => None,
    }
}

/// Formats an arbitrary integer status/result code into a descriptive string.
pub fn format_result_code(code: u32) -> String {
    if let Some(info) = lookup_error_code(code) {
        format!("{} (0x{:08X})", info.name, code)
    } else if code == 0 {
        "SUCCESS (0x00000000)".to_string()
    } else {
        format!("0x{:08X}", code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_win32_success() {
        let info = lookup_win32_error(0).expect("ERROR_SUCCESS should resolve");
        assert_eq!(info.name, "ERROR_SUCCESS");
        assert_eq!(info.severity, ErrorSeverity::Success);
        assert!(!info.severity.is_failure());
    }

    #[test]
    fn test_lookup_ntstatus_success() {
        let info = lookup_ntstatus(0).expect("STATUS_SUCCESS should resolve");
        assert_eq!(info.name, "STATUS_SUCCESS");
        assert_eq!(info.severity, ErrorSeverity::Success);
        assert!(!info.severity.is_failure());
    }

    #[test]
    fn test_lookup_win32_access_denied() {
        let info = lookup_win32_error(5).expect("ERROR_ACCESS_DENIED should resolve");
        assert_eq!(info.name, "ERROR_ACCESS_DENIED");
        assert_eq!(info.severity, ErrorSeverity::Error);
        assert!(info.severity.is_failure());
    }

    #[test]
    fn test_lookup_ntstatus_object_not_found() {
        let info =
            lookup_ntstatus(0xC000_0034).expect("STATUS_OBJECT_NAME_NOT_FOUND should resolve");
        assert_eq!(info.name, "STATUS_OBJECT_NAME_NOT_FOUND");
        assert_eq!(info.severity, ErrorSeverity::Error);
        assert!(info.severity.is_failure());
    }

    #[test]
    fn test_lookup_ntstatus_elevation_required() {
        let info = lookup_ntstatus(0xC000_042C).expect("STATUS_ELEVATION_REQUIRED should resolve");
        assert_eq!(info.name, "STATUS_ELEVATION_REQUIRED");
        assert_eq!(info.severity, ErrorSeverity::Error);
        assert!(info.severity.is_failure());
    }

    #[test]
    fn test_format_result_code_known_and_unknown() {
        assert_eq!(format_result_code(0), "ERROR_SUCCESS (0x00000000)");
        assert_eq!(format_result_code(5), "ERROR_ACCESS_DENIED (0x00000005)");
        assert_eq!(
            format_result_code(0xC000_0034),
            "STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)"
        );
        assert_eq!(format_result_code(0x1234_5678), "0x12345678");
    }

    #[test]
    fn test_severity_predicate() {
        assert!(!ErrorSeverity::Success.is_failure());
        assert!(!ErrorSeverity::Informational.is_failure());
        assert!(ErrorSeverity::Warning.is_failure());
        assert!(ErrorSeverity::Error.is_failure());
    }
}
