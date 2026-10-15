// wstrace - Privilege & Elevation Detection (Zero-Elevation Architecture)

use std::mem::size_of;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationLevel {
    /// Running as standard unprivileged user (UAC filtered token)
    StandardUser,
    /// Running with elevated Administrator privileges
    Elevated,
    /// Failed to inspect token (defaults to unprivileged safety)
    Unknown,
}

impl ElevationLevel {
    pub fn is_elevated(&self) -> bool {
        matches!(self, Self::Elevated)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StandardUser => "StandardUser (Unprivileged)",
            Self::Elevated => "Elevated (Administrator)",
            Self::Unknown => "Unknown (Defaulting to Unprivileged)",
        }
    }
}

/// Detects whether the current process is running with elevated privileges.
///
/// This inspection queries `TokenElevation` on the process primary token.
/// It operates completely in userland without triggering UAC elevation dialogs.
pub fn detect_elevation() -> ElevationLevel {
    unsafe {
        let current_process = GetCurrentProcess();
        let mut token_handle: HANDLE = std::ptr::null_mut();

        if OpenProcessToken(current_process, TOKEN_QUERY, &mut token_handle) == 0 {
            return ElevationLevel::Unknown;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let status = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        CloseHandle(token_handle);

        if status == 0 {
            return ElevationLevel::Unknown;
        }

        if elevation.TokenIsElevated != 0 {
            ElevationLevel::Elevated
        } else {
            ElevationLevel::StandardUser
        }
    }
}

/// Convenience helper to check if running elevated.
pub fn is_elevated() -> bool {
    detect_elevation().is_elevated()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_elevation_returns_valid_variant() {
        let level = detect_elevation();
        // Running on standard Windows test environment, must resolve without panic
        assert!(matches!(
            level,
            ElevationLevel::StandardUser | ElevationLevel::Elevated | ElevationLevel::Unknown
        ));
    }

    #[test]
    fn test_elevation_level_string_mapping() {
        assert_eq!(
            ElevationLevel::StandardUser.as_str(),
            "StandardUser (Unprivileged)"
        );
        assert_eq!(
            ElevationLevel::Elevated.as_str(),
            "Elevated (Administrator)"
        );
        assert_eq!(
            ElevationLevel::Unknown.as_str(),
            "Unknown (Defaulting to Unprivileged)"
        );
    }

    #[test]
    fn test_elevation_is_elevated_predicate() {
        assert!(!ElevationLevel::StandardUser.is_elevated());
        assert!(ElevationLevel::Elevated.is_elevated());
        assert!(!ElevationLevel::Unknown.is_elevated());
    }
}
