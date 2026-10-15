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
}
