#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

pub fn parse_ethernet(frame: &[u8]) -> Option<EthernetHeader> {
    let (dst, buff) = frame.split_first_chunk::<6>()?;
    let (src, buff) = buff.split_first_chunk::<6>()?;
    let (ethertype, _) = buff.split_first_chunk::<2>()?;

    Some(EthernetHeader {
        dst: *dst,
        src: *src,
        ethertype: u16::from_be_bytes(*ethertype),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ARP-запрос из твоего захвата tcpdump -XX (42 байта)
    const ARP_REQ: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, 0x6b, 0x06, 0x4f, 0xf4, 0x2e, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xf6, 0x6b, 0x06, 0x4f, 0xf4, 0x2e, 0x0a, 0x00,
        0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x14,
    ];

    #[test]
    fn parses_arp_request_frame() {
        let eth = parse_ethernet(&ARP_REQ).unwrap();
        assert_eq!(eth.dst, [0xff; 6]);
        assert_eq!(eth.src, [0xf6, 0x6b, 0x06, 0x4f, 0xf4, 0x2e]);
        assert_eq!(eth.ethertype, 0x0806);
    }

    #[test]
    fn short_frame_is_none() {
        assert!(parse_ethernet(&[0u8; 13]).is_none());
    }
}
