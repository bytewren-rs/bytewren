#[cfg(target_os = "linux")]
mod raw_socket_linux;
pub use raw_socket_linux::capture_packet;
pub use raw_socket_linux::CapturedPacket;
pub use raw_socket_linux::PacketMeta;

#[cfg(target_os = "windows")]
mod raw_socket_windows;