use std::process::Command;
use tun_tap::{Iface, Mode};

#[derive(Debug)]
#[repr(u16)]
enum EtherType {
    IpV4 = 0x0800,
    IpV6 = 0x86DD,
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IpV4,
            0x86DD => EtherType::IpV6,
            _ => panic!("EtherType Not Supported"),
        }
    }
}

#[derive(Debug)]
struct EthernetHeader {
    dest_mac_address: [u8; 6],
    source_mac_address: [u8; 6],
    ether_type: EtherType,
}

impl EthernetHeader {
    pub fn from_bytes(bytes: [u8; 14]) -> Self {
        Self {
            dest_mac_address: bytes[..6].try_into().unwrap(),
            source_mac_address: bytes[6..12].try_into().unwrap(),
            ether_type: EtherType::from(u16::from_be_bytes([bytes[12], bytes[13]])),
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

        let eth_header = EthernetHeader::from_bytes(buffer[4..4 + 14].try_into().unwrap());
        println!("{eth_header:x?}");
    }
}
