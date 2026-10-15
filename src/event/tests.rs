use super::*;

#[test]
fn test_event_category_string_mapping() {
    assert_eq!(EventCategory::FileSystem.as_str(), "FILE");
    assert_eq!(EventCategory::Registry.as_str(), "REG");
    assert_eq!(EventCategory::Network.as_str(), "NET");
    assert_eq!(EventCategory::Process.as_str(), "PROC");
    assert_eq!(EventCategory::Memory.as_str(), "MEM");
    assert_eq!(EventCategory::Error.as_str(), "ERR");
}

#[test]
fn test_event_lifecycle_and_serialization() {
    let event = TraceEvent::new(
        1,
        4096,
        12,
        EventCategory::FileSystem,
        "NtCreateFile",
        "\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll",
        "STATUS_SUCCESS",
        false,
    );

    assert_eq!(event.id, 1);
    assert_eq!(event.pid, 4096);
    assert_eq!(event.tid, 12);
    assert_eq!(event.category, EventCategory::FileSystem);
    assert!(!event.is_failure);

    let serialized = serde_json::to_string(&event).expect("Serialization must succeed");
    let deserialized: TraceEvent =
        serde_json::from_str(&serialized).expect("Deserialization must succeed");

    assert_eq!(deserialized.id, event.id);
    assert_eq!(deserialized.pid, event.pid);
    assert_eq!(deserialized.operation, event.operation);
    assert_eq!(deserialized.target, event.target);
    assert_eq!(deserialized.result, event.result);
    assert_eq!(deserialized.is_failure, event.is_failure);
}

#[test]
fn test_event_builder_methods() {
    let event = TraceEvent::new(
        2,
        1000,
        1,
        EventCategory::FileSystem,
        "NtOpenFile",
        "C:\\secret.txt",
        "",
        false,
    )
    .with_duration(150)
    .with_details("handle=0x123")
    .with_status_code(5); // ERROR_ACCESS_DENIED

    assert_eq!(event.duration_us, 150);
    assert_eq!(event.details, "handle=0x123");
    assert_eq!(event.result, "ERROR_ACCESS_DENIED (0x00000005)");
    assert!(event.is_failure);

    let event_unmapped = TraceEvent::new(
        3,
        1000,
        1,
        EventCategory::FileSystem,
        "NtOpenFile",
        "C:\\file.txt",
        "",
        false,
    )
    .with_status_code(0xC000_0999);

    assert_eq!(event_unmapped.result, "0xC0000999");
    assert!(event_unmapped.is_failure);

    let event_zero_nt = TraceEvent::new(
        4,
        1000,
        1,
        EventCategory::FileSystem,
        "NtOpenFile",
        "C:\\file.txt",
        "",
        false,
    )
    .with_status_code(0);

    assert_eq!(event_zero_nt.result, "STATUS_SUCCESS (0x00000000)");
    assert!(!event_zero_nt.is_failure);

    let event_zero_win32 = TraceEvent::new(
        5,
        1000,
        1,
        EventCategory::FileSystem,
        "CreateFileW",
        "C:\\file.txt",
        "",
        false,
    )
    .with_status_code(0);

    assert_eq!(event_zero_win32.result, "ERROR_SUCCESS (0x00000000)");
    assert!(!event_zero_win32.is_failure);

    let event_explicit_nt = TraceEvent::new(
        6,
        1000,
        1,
        EventCategory::FileSystem,
        "CustomFileOp",
        "C:\\file.txt",
        "",
        false,
    )
    .with_ntstatus(0);

    assert_eq!(event_explicit_nt.result, "STATUS_SUCCESS (0x00000000)");
    assert!(!event_explicit_nt.is_failure);
}
