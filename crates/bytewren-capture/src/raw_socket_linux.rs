use libc::{
    AF_INET, AF_PACKET, ETH_P_ALL, SIOCGIFINDEX, SOCK_DGRAM, SOCK_RAW, c_char, c_int, c_void,
    ifreq, sockaddr, sockaddr_ll, socklen_t,
};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

const _: () = assert!(size_of::<sockaddr_ll>() <= socklen_t::MAX as usize);

#[expect(
    clippy::cast_possible_truncation,
    reason = "proven by the const assertion above"
)]
const SOCKADDR_LL_LEN: socklen_t = size_of::<sockaddr_ll>() as socklen_t;

const _: () = assert!(AF_PACKET <= u16::MAX as c_int && AF_PACKET >= 0);

#[expect(
    clippy::cast_possible_truncation,
    reason = "proven by the const assertion above"
)]
const AF_PACKET_U16: u16 = AF_PACKET as u16;

const _: () = assert!(ETH_P_ALL <= u16::MAX as c_int && ETH_P_ALL >= 0);

#[expect(
    clippy::cast_possible_truncation,
    reason = "proven by the const assertion above"
)]
const ETH_P_ALL_U16: u16 = ETH_P_ALL as u16;

#[derive(Debug)]
pub struct PacketMeta {
    len: usize,
    hatype: u16,
    pkttype: u8,
}

impl PacketMeta {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn hatype(&self) -> u16 {
        self.hatype
    }
    pub fn pkttype(&self) -> u8 {
        self.pkttype
    }
}

#[derive(Debug)]
pub struct CapturedPacket {
    buf: Vec<u8>,
    meta: PacketMeta,
}

impl CapturedPacket {
    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }

    pub fn meta(&self) -> &PacketMeta {
        &self.meta
    }
}

struct RawSocket {
    fd: RawFd,
}

impl RawSocket {
    fn new(domain: c_int, ty: c_int, protocol: c_int) -> io::Result<Self> {
        // SAFETY: `socket` takes three `c_int` values by value and no pointers, so
        // it has no access to memory owned by the caller. Unsupported arguments are
        // reported as `-1` plus `errno`, never as undefined behaviour, so there is
        // no precondition for the caller to uphold.
        let fd = unsafe { libc::socket(domain, ty, protocol) };

        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(RawSocket { fd })
    }

    fn bind(&self, addr: &sockaddr_ll) -> io::Result<()> {
        // SAFETY: `self.fd` is an open descriptor by the type invariant documented
        // on `Drop`. `addr` is a live `&sockaddr_ll`, so the pointer is non-null,
        // aligned and valid for reads of `size_of::<sockaddr_ll>()` bytes for the
        // duration of the call. `bind` reinterprets it as `sockaddr` but reads only
        // the number of bytes given by the third argument, which is exactly that
        // size, so it cannot read past the end. The kernel copies what it needs and
        // does not retain the pointer after returning.
        let ret = unsafe {
            libc::bind(
                self.fd,
                addr as *const sockaddr_ll as *const sockaddr,
                SOCKADDR_LL_LEN,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recvfrom(&self, buf: &mut [u8]) -> io::Result<PacketMeta> {
        // SAFETY: all-zero is a valid bit pattern for `sockaddr_ll`: every field is
        // an integer or an array of integers, and zero is a valid value for each.
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        let mut addrlen = SOCKADDR_LL_LEN;

        // SAFETY: `self.fd` is an open descriptor by the type invariant documented
        // on `Drop`. `buf.as_mut_ptr()` is valid for writes of `buf.len()` bytes and
        // `buf.len()` is passed as the length, so the kernel cannot write past the
        // end. `addr` is a live local, fully initialised above and valid for writes
        // of `size_of::<sockaddr_ll>()` bytes; `addrlen` is initialised to that size
        // and is an in-out parameter the kernel overwrites with the length it
        // actually produced. Neither pointer is retained after the call returns.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0, // flags: no MSG_TRUNC yet, so truncation is currently invisible
                &mut addr as *mut sockaddr_ll as *mut sockaddr,
                &mut addrlen,
            )
        };
        if n == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(PacketMeta {
                len: n as usize,
                hatype: addr.sll_hatype,
                pkttype: addr.sll_pkttype,
            })
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // The result is intentionally discarded: `drop` has no way to report an
        // error, and on Linux the descriptor is released even when `close` fails
        // with `EINTR` — retrying would close a descriptor that has since been
        // reused by another thread.
        //
        // SAFETY: `self.fd` comes from a successful `libc::socket` call in
        // `RawSocket::new`, which returns an error instead of constructing the
        // value when the call fails. The field is private and `RawSocket` is
        // constructed nowhere else, so it always holds an open descriptor.
        //
        // `drop` runs at most once per value, and `RawSocket` does not implement
        // `Clone`, so no two values can hold the same descriptor number. The
        // descriptor is therefore closed exactly once. Do not derive `Clone`:
        // the kernel hands out the lowest free descriptor number, so a double
        // close can silently close an unrelated file opened in between.
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn get_iface_index(name: &str) -> io::Result<c_int> {
    let tmp = RawSocket::new(AF_INET, SOCK_DGRAM, 0)?;

    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "имя содержит нулевой байт"))?;
    let name_bytes = c_name.as_bytes_with_nul();

    // SAFETY: `c_char` is an integer type with the same size and alignment as `u8`
    // (both 1), and every bit pattern is valid for both, so these bytes are a valid
    // `[c_char]` whether `c_char` is signed on this target or not. `name_bytes`
    // borrows `c_name`, which outlives the slice and is never mutated while it is
    // alive, so the pointer stays valid for reads of `name_bytes.len()` bytes.
    let name_bytes_i8: &[c_char] = unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, name_bytes.len())
    };

    // SAFETY: all-zero is a valid bit pattern for `ifreq`. `ifr_name` is an array
    // of `c_char`, an integer type. `ifr_ifru` is a union whose variants are
    // integer types, arrays of `c_char`, structs built from those, and a
    // `*mut c_char`. Zero is valid for each: for the raw pointer it is null, which
    // is a legal value for `*mut T` — unlike a reference, which must never be null.
    let mut ifr: ifreq = unsafe { mem::zeroed() };

    if name_bytes_i8.len() > ifr.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "имя интерфейса слишком длинное",
        ));
    }
    ifr.ifr_name
        .get_mut(..name_bytes_i8.len())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "имя интерфейса слишком длинное",
            )
        })?
        .copy_from_slice(name_bytes_i8);

    // SAFETY: `tmp.fd` is an open descriptor by the type invariant documented on
    // `Drop`. `ioctl` is variadic, so the compiler cannot check that the third
    // argument matches the request number; `SIOCGIFINDEX` is documented in
    // `netdevice(7)` to take a `*mut ifreq`, which is what is passed here. `ifr` is
    // fully initialised and valid for reads and writes of `size_of::<ifreq>()`
    // bytes for the duration of the call.
    let res = unsafe { libc::ioctl(tmp.fd, SIOCGIFINDEX, &mut ifr) };
    if res == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the call above returned successfully, and `SIOCGIFINDEX` is documented
    // to fill in the `ifru_ifindex` variant, so that is the variant currently stored
    // in the union. This read must stay after the error check: on failure the kernel
    // leaves the union as we passed it, and no variant would be known to be active.
    let ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };
    Ok(ifindex)
}

fn create_sockaddr_ll(ifindex: c_int) -> sockaddr_ll {
    // SAFETY: all-zero is a valid bit pattern for `sockaddr_ll`: every field is an
    // integer or an array of integers, and zero is a valid value for each.
    let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = AF_PACKET_U16;
    addr.sll_protocol = ETH_P_ALL_U16.to_be();
    addr.sll_ifindex = ifindex;
    addr
}

pub fn capture_packet(ifname: &str) -> io::Result<CapturedPacket> {
    // 1. Получить индекс интерфейса
    let ifindex = get_iface_index(ifname)?;

    // 2. Создать raw-сокет AF_PACKET + SOCK_RAW + ETH_P_ALL (в сетевом порядке)
    let sock = RawSocket::new(AF_PACKET, SOCK_RAW, 0)?;

    // 3. Подготовить адрес интерфейса (sockaddr_ll)
    let addr = create_sockaddr_ll(ifindex);

    // 4. Привязать сокет к интерфейсу
    sock.bind(&addr)?;

    // 5. Подготовить буфер и принять пакет
    let mut buf = vec![0u8; 65536];
    let meta = sock.recvfrom(&mut buf)?;
    buf.truncate(meta.len());

    Ok(CapturedPacket { buf, meta })
}
