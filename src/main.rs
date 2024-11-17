use std::process::Command;
use tun_tap::{Iface, Mode};

#[derive(Debug)]
#[repr(u16)]
enum EtherType {
    IpV4 = 0x0800,
    IpV6 = 0x86DD,
    Arp = 0x0806,
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IpV4,
            0x86DD => EtherType::IpV6,
            0x0806 => EtherType::Arp,
            _ => panic!("EtherType Not Supported"),
        }
    }
}

#[derive(Debug)]
struct EthernetHeader {
    dest_mac_address: [u8; 6],
    source_mac_address: [u8; 6],
    ether_type: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            dest_mac_address: bytes[..6].try_into().unwrap(),
            source_mac_address: bytes[6..12].try_into().unwrap(),
            ether_type: EtherType::from(u16::from_be_bytes([bytes[12], bytes[13]])),
            payload: bytes[14..].to_vec(),
        }
    }
}

#[derive(Debug)]
struct IpV4Header {
    version: u8,
    pub header_length: u8,
    protocol: u8,
    checksum: u16,
    source_address: [u8; 4],
    destination_address: [u8; 4],
}

impl IpV4Header {
    pub fn from_ethernet_payload(payload: &[u8]) -> Self {
        // The IP version is in the first 4 bits but considering network order is big endian,
        // we get the "last" 4 bits instead
        let version = payload[0] >> 4;
        let header_length = payload[0] & 0xf;
        let protocol = payload[9];
        let checksum = u16::from_be_bytes([payload[10], payload[11]]);
        let source_address: [u8; 4] = payload[12..16].try_into().unwrap();
        let destination_address = payload[16..20].try_into().unwrap();
        Self {
            version,
            header_length,
            protocol,
            checksum,
            source_address,
            destination_address,
        }
    }
}

#[derive(Debug)]
struct UdpHeader {
    source_port: u16,
    destination_port: u16,
    pub length: u16,
    checksum: u16,
    data: Vec<u8>,
}

impl UdpHeader {
    pub fn from_ethernet_payload(payload: &[u8]) -> Self {
        let source_port = u16::from_be_bytes([payload[0], payload[1]]);
        let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
        let length = u16::from_be_bytes([payload[4], payload[5]]);
        let checksum = u16::from_be_bytes([payload[6], payload[7]]);
        let data = payload[8..].to_vec();
        Self {
            source_port,
            destination_port,
            length,
            checksum,
            data,
        }
    }
}

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execte {}", cmd);
}

fn main() {
    let iface = Iface::new("tap0", Mode::Tap).unwrap();

    cmd(
        "ip",
        &["addr", "add", "192.168.0.1/24", "dev", iface.name()],
    );
    cmd("ip", &["link", "set", "up", iface.name()]);

    let mut buffer = vec![0; 1504];

    loop {
        let packet_length = iface.recv(&mut buffer).unwrap();
        let protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        if protocol != EtherType::IpV4 as u16 {
            continue;
        }

        let eth_header = EthernetHeader::from_bytes(buffer[4..packet_length].try_into().unwrap());
        let ip_header = IpV4Header::from_ethernet_payload(&eth_header.payload);

        println!("{eth_header:x?}\n{ip_header:?}\nFull Data Length: {packet_length}");
    }
}
