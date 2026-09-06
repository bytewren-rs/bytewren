#[cfg(not(target_os = "linux"))]
compile_error!(
    "bytewren-capture supports Linux only: capture is built on AF_PACKET, which has \
     no equivalent on other platforms"
);

#[cfg(target_os = "linux")]
mod raw_socket_linux;

#[cfg(target_os = "linux")]
pub use raw_socket_linux::{CapturedPacket, PacketMeta, capture_packet};
