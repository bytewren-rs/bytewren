use libc::{
    AF_INET, AF_PACKET, ETH_P_ALL, SIOCGIFINDEX, SOCK_DGRAM, SOCK_RAW, c_char, c_int, c_void,
    ifreq, sockaddr, sockaddr_ll,
};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

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
        // SAFETY: нужно написать правильный комментарий.
        let fd = unsafe { libc::socket(domain, ty, protocol) };

        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(RawSocket { fd })
    }

    fn bind(&self, addr: &sockaddr_ll) -> io::Result<()> {
        // SAFETY: нужно написать правильный комментарий.
        let ret = unsafe {
            libc::bind(
                self.fd,
                addr as *const sockaddr_ll as *const sockaddr,
                u32::try_from(mem::size_of::<sockaddr_ll>()).map_err(io::Error::other)?,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recvfrom(&self, buf: &mut [u8]) -> io::Result<PacketMeta> {
        // SAFETY: нужно написать правильный комментарий.
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        let mut addrlen = u32::try_from(mem::size_of::<sockaddr_ll>()).map_err(io::Error::other)?;

        // SAFETY: нужно написать правильный комментарий.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
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
        // SAFETY: нужно написать правильный комментарий.
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub fn get_iface_index(name: &str) -> io::Result<c_int> {
    let tmp = RawSocket::new(AF_INET, SOCK_DGRAM, 0)?;

    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "имя содержит нулевой байт"))?;
    let name_bytes = c_name.as_bytes_with_nul();

    // SAFETY: нужно написать правильный комментарий.
    let name_bytes_i8: &[c_char] = unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, name_bytes.len())
    };

    // SAFETY: нужно написать правильный комментарий.
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

    // SAFETY: нужно написать правильный комментарий.
    let ret = unsafe {
        let res = libc::ioctl(tmp.fd, SIOCGIFINDEX, &mut ifr);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_ifindex
    };
    Ok(ret)
}

pub fn create_sockaddr_ll(ifindex: c_int) -> io::Result<sockaddr_ll> {
    // SAFETY: нужно написать правильный комментарий.
    let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = u16::try_from(AF_PACKET).map_err(io::Error::other)?;
    addr.sll_protocol = u16::try_from(ETH_P_ALL).map_err(io::Error::other)?.to_be();
    addr.sll_ifindex = ifindex;
    Ok(addr)
}

pub fn capture_packet(ifname: &str) -> io::Result<CapturedPacket> {
    // 1. Получить индекс интерфейса
    let ifindex = get_iface_index(ifname)?;

    // 2. Создать raw-сокет AF_PACKET + SOCK_RAW + ETH_P_ALL (в сетевом порядке)
    let sock = RawSocket::new(AF_PACKET, SOCK_RAW, 0)?;

    // 3. Подготовить адрес интерфейса (sockaddr_ll)
    let addr = create_sockaddr_ll(ifindex)?;

    // 4. Привязать сокет к интерфейсу
    sock.bind(&addr)?;

    // 5. Подготовить буфер и принять пакет
    let mut buf = vec![0u8; 65536];
    let meta = sock.recvfrom(&mut buf)?;
    buf.truncate(meta.len());

    Ok(CapturedPacket { buf, meta })
}
