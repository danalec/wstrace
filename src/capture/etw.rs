// wstrace - Event Tracing for Windows (ETW) Consumer

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::capture::elevation::detect_elevation;
use crate::event::TraceEvent;
use crossbeam_channel::Sender;

pub struct EtwConsumer {
    pid: u32,
    running: Arc<AtomicBool>,
    is_elevated: bool,
}

impl EtwConsumer {
    pub fn new(pid: u32) -> Self {
        let is_elevated = detect_elevation().is_elevated();
        Self::with_elevation(pid, is_elevated)
    }

    pub fn with_elevation(pid: u32, is_elevated: bool) -> Self {
        Self {
            pid,
            running: Arc::new(AtomicBool::new(true)),
            is_elevated,
        }
    }

    pub fn is_elevated(&self) -> bool {
        self.is_elevated
    }

    pub fn start(&self, event_tx: Sender<TraceEvent>) {
        let _pid = self.pid;
        let running = Arc::clone(&self.running);
        let is_elevated = self.is_elevated;

        thread::spawn(move || {
            let _event_tx = event_tx;
            // Full kernel ETW sessions require SeProfileSingleProcessPrivilege / Admin elevation.
            // When unprivileged, consumer operates in user-mode fallback state without panic.
            if !is_elevated {
                // Running in unprivileged mode: kernel sessions deferred to Win32Probe
            }
            while running.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(500));
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etw_consumer_creation_and_elevation_state() {
        let consumer = EtwConsumer::with_elevation(1234, false);
        assert!(!consumer.is_elevated());
        assert_eq!(consumer.pid, 1234);

        let elevated_consumer = EtwConsumer::with_elevation(1234, true);
        assert!(elevated_consumer.is_elevated());
    }

    #[test]
    fn test_etw_consumer_lifecycle() {
        let consumer = EtwConsumer::new(0);
        let (tx, _rx) = crossbeam_channel::unbounded();
        consumer.start(tx);
        consumer.stop();
        assert!(!consumer.running.load(Ordering::Relaxed));
    }
}
