#[cfg(target_os = "linux")]
mod raw_socket_linux;
pub use raw_socket_linux::capture_packet;

#[cfg(target_os = "windows")]
mod raw_socket_windows;