// wstrace - Real-Time Unprivileged Network Probe (TCP / UDP via IP Helper)

use std::collections::HashSet;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::Local;
use crossbeam_channel::Sender;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use crate::event::{EventCategory, TraceEvent};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketRecord {
    pub protocol: &'static str,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
}

pub struct NetworkProbe {
    pid: u32,
    target_name: String,
    running: Arc<AtomicBool>,
}

impl NetworkProbe {
    pub fn new(pid: u32, target_name: String) -> Self {
        Self {
            pid,
            target_name,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn start(&self, event_tx: Sender<TraceEvent>) {
        let monitored_pid = self.pid;
        let target_name = self.target_name.clone();
        let running = Arc::clone(&self.running);

        thread::spawn(move || {
            let mut known_sockets: HashSet<SocketRecord> = HashSet::new();
            let mut event_id_counter: u64 = 50_000_000;

            while running.load(Ordering::Relaxed) {
                let current_sockets = query_active_sockets(monitored_pid);

                for sock in &current_sockets {
                    if !known_sockets.contains(sock) {
                        event_id_counter += 1;
                        let now = Local::now().format("%H:%M:%S.%3f").to_string();

                        let target_display = if sock.remote_port > 0 {
                            format!(
                                "{}:{} -> {}:{}",
                                sock.local_addr,
                                sock.local_port,
                                sock.remote_addr,
                                sock.remote_port
                            )
                        } else {
                            format!("{}:{} ({})", sock.local_addr, sock.local_port, sock.state)
                        };

                        let operation = match (sock.protocol, sock.state.as_str()) {
                            ("TCP", "LISTEN") => "TcpListen".to_string(),
                            ("TCP", "ESTABLISHED") => "TcpConnect".to_string(),
                            ("TCP", "CLOSE_WAIT") | ("TCP", "TIME_WAIT") | ("TCP", "CLOSED") => {
                                "TcpDisconnect".to_string()
                            }
                            ("UDP", _) => "UdpBind".to_string(),
                            _ => format!("{}Active", sock.protocol),
                        };

                        let details = format!(
                            "Proto: {}, State: {}, Process: {} (PID: {})",
                            sock.protocol, sock.state, target_name, sock.pid
                        );

                        let event = TraceEvent {
                            id: event_id_counter,
                            timestamp: now,
                            pid: sock.pid,
                            tid: 0,
                            category: EventCategory::Network,
                            operation,
                            target: target_display,
                            result: "STATUS_SUCCESS".to_string(),
                            duration_us: 0,
                            is_failure: false,
                            details,
                        };

                        if event_tx.send(event).is_err() {
                            return;
                        }
                    }
                }

                // Retain only currently active sockets to detect reconnection cycles
                known_sockets = current_sockets;

                thread::sleep(Duration::from_millis(250));
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub fn query_active_sockets(filter_pid: u32) -> HashSet<SocketRecord> {
    let mut records = HashSet::new();

    // Query IPv4 TCP Connections
    query_tcp_ipv4(filter_pid, &mut records);

    // Query IPv4 UDP Listeners / Endpoints
    query_udp_ipv4(filter_pid, &mut records);

    records
}

fn query_tcp_ipv4(filter_pid: u32, records: &mut HashSet<SocketRecord>) {
    let mut buffer_size: u32 = 0;

    unsafe {
        let ret = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut buffer_size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != ERROR_INSUFFICIENT_BUFFER {
            return;
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let ret = GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut c_void,
            &mut buffer_size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != NO_ERROR {
            return;
        }

        let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let num_entries = (*table).dwNumEntries as usize;
        let rows_ptr = std::ptr::addr_of!((*table).table) as *const MIB_TCPROW_OWNER_PID;

        for i in 0..num_entries {
            let row = *rows_ptr.add(i);

            if filter_pid != 0 && row.dwOwningPid != filter_pid {
                continue;
            }

            let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string();
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)).to_string();
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            let state = tcp_state_to_str(row.dwState).to_string();

            records.insert(SocketRecord {
                protocol: "TCP",
                local_addr: local_ip,
                local_port,
                remote_addr: remote_ip,
                remote_port,
                state,
                pid: row.dwOwningPid,
            });
        }
    }
}

fn query_udp_ipv4(filter_pid: u32, records: &mut HashSet<SocketRecord>) {
    let mut buffer_size: u32 = 0;

    unsafe {
        let ret = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut buffer_size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != ERROR_INSUFFICIENT_BUFFER {
            return;
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let ret = GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut c_void,
            &mut buffer_size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != NO_ERROR {
            return;
        }

        let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
        let num_entries = (*table).dwNumEntries as usize;
        let rows_ptr = std::ptr::addr_of!((*table).table) as *const MIB_UDPROW_OWNER_PID;

        for i in 0..num_entries {
            let row = *rows_ptr.add(i);

            if filter_pid != 0 && row.dwOwningPid != filter_pid {
                continue;
            }

            let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string();
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);

            records.insert(SocketRecord {
                protocol: "UDP",
                local_addr: local_ip,
                local_port,
                remote_addr: "*".to_string(),
                remote_port: 0,
                state: "BOUND".to_string(),
                pid: row.dwOwningPid,
            });
        }
    }
}

fn tcp_state_to_str(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_to_str_mapping() {
        assert_eq!(tcp_state_to_str(1), "CLOSED");
        assert_eq!(tcp_state_to_str(2), "LISTEN");
        assert_eq!(tcp_state_to_str(5), "ESTABLISHED");
        assert_eq!(tcp_state_to_str(8), "CLOSE_WAIT");
        assert_eq!(tcp_state_to_str(11), "TIME_WAIT");
        assert_eq!(tcp_state_to_str(99), "UNKNOWN");
    }

    #[test]
    fn test_query_active_sockets_runs_without_panic() {
        let current_pid = std::process::id();
        let sockets = query_active_sockets(current_pid);
        // Current test process may or may not have open sockets, but call must not panic
        let _ = sockets.len();
    }

    #[test]
    fn test_network_probe_lifecycle() {
        let probe = NetworkProbe::new(0, "SYSTEM-WIDE".to_string());
        let (tx, _rx) = crossbeam_channel::unbounded();
        probe.start(tx);
        probe.stop();
        assert!(!probe.running.load(Ordering::Relaxed));
    }
}
