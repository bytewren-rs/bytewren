use libc::{
    AF_INET, AF_PACKET, ETH_P_ALL, SIOCGIFINDEX, SOCK_DGRAM, SOCK_RAW, c_char, c_int, c_void,
    ifreq, sockaddr, sockaddr_ll,
};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

pub struct RawSocket {
    fd: RawFd,
}

impl RawSocket {
    pub fn new(domain: c_int, ty: c_int, protocol: c_int) -> io::Result<Self> {
        let fd = unsafe { libc::socket(domain, ty, protocol) };

        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(RawSocket { fd })
    }

    pub fn bind(&self, addr: &sockaddr_ll) -> io::Result<()> {
        let ret = unsafe {
            libc::bind(
                self.fd,
                addr as *const sockaddr_ll as *const sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn recvfrom(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        let mut addrlen = mem::size_of::<sockaddr_ll>() as u32;
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
            Ok(n as usize)
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
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
    let name_bytes_i8: &[c_char] = unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, name_bytes.len())
    };

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    if name_bytes_i8.len() > ifr.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "имя интерфейса слишком длинное",
        ));
    }
    ifr.ifr_name[..name_bytes_i8.len()].copy_from_slice(name_bytes_i8);

    let ret = unsafe {
        let res = libc::ioctl(tmp.fd, SIOCGIFINDEX, &mut ifr);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_ifindex
    };
    Ok(ret)
}

pub fn create_sockaddr_ll(ifindex: c_int) -> sockaddr_ll {
    let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = AF_PACKET as u16;
    addr.sll_protocol = (ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    addr
}

pub fn capture_packet(ifname: &str) -> io::Result<Vec<u8>> {
    // 1. Получить индекс интерфейса
    let ifindex = get_iface_index(ifname)?;

    // 2. Создать raw-сокет AF_PACKET + SOCK_RAW + ETH_P_ALL (в сетевом порядке)
    let sock = RawSocket::new(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as c_int)?;

    // 3. Подготовить адрес интерфейса (sockaddr_ll)
    let addr = create_sockaddr_ll(ifindex);

    // 4. Привязать сокет к интерфейсу
    sock.bind(&addr)?;

    // 5. Подготовить буфер и принять пакет
    let mut buf = vec![0u8; 65536];
    let n = sock.recvfrom(&mut buf)?;
    buf.truncate(n);

    Ok(buf)
}
