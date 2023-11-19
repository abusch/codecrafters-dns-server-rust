// Uncomment this block to pass the first stage
// use std::net::UdpSocket;

use std::{net::UdpSocket, str::FromStr};

use bitvec::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);
                println!("Received {} bytes from {}", size, source);
                let msg = DnsMessage {
                    header: Header {
                        id: 1234,
                        qr: true,
                        qd_count: 1,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        qname: "codecrafters.io".parse()?,
                        qtype: QType::A,
                        qclass: QClass::IN,
                    }],
                };
                let response = msg.to_bytes();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }

    Ok(())
}

pub struct DnsMessage {
    header: Header,
    questions: Vec<Question>,
}

impl DnsMessage {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put(self.header.to_bytes());
        for q in &self.questions {
            buf.put(q.to_bytes());
        }

        buf.freeze()
    }
}

pub struct Question {
    qname: QName,
    qtype: QType,
    qclass: QClass,
}

impl Question {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put(self.qname.to_bytes());
        buf.put_u16(self.qtype as u16);
        buf.put_u16(self.qclass as u16);

        buf.freeze()
    }
}

pub struct QName(Vec<Label>);

impl QName {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        for label in &self.0 {
            buf.put(label.to_bytes());
        }
        buf.put_u8(0);

        buf.freeze()
    }
}

impl FromStr for QName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let labels = s
            .split('.')
            .map(|label| Label(label.as_bytes().to_vec()))
            .collect();
        Ok(Self(labels))
    }
}

pub struct Label(Vec<u8>);

impl Label {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.0.len() as u8);
        buf.put(self.0.as_slice());

        buf.freeze()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum QType {
    A = 1,       // a host address
    NS = 2,      // an authoritative name server
    MD = 3,      // a mail destination (Obsolete - use MX)
    MF = 4,      // a mail forwarder (Obsolete - use MX)
    CNAME = 5,   // the canonical name for an alias
    SOA = 6,     // marks the start of a zone of authority
    MB = 7,      // a mailbox domain name (EXPERIMENTAL)
    MG = 8,      // a mail group member (EXPERIMENTAL)
    MR = 9,      // a mail rename domain name (EXPERIMENTAL)
    NULL = 10,   //  a null RR (EXPERIMENTAL)
    WKS = 11,    //  a well known service description
    PTR = 12,    //  a domain name pointer
    HINFO = 13,  //  host information
    MINFO = 14,  //  mailbox or mail list information
    MX = 15,     //  mail exchange
    TXT = 16,    //  text strings
    AXFR = 252,  // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    STAR = 255,  // A request for all records
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum QClass {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    id: u16,
    qr: bool,
    opcode: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    reserved: u8,
    response_code: u8,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl Header {
    pub const TEST: Self = Self {
        id: 1234,
        qr: true,
        opcode: 0,
        authoritative_answer: false,
        truncation: false,
        recursion_desired: false,
        recursion_available: false,
        reserved: 0,
        response_code: 0,
        qd_count: 0,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    pub fn to_bytes(&self) -> Bytes {
        let mut data = [0u8; 12];
        let bits = data.view_bits_mut::<Msb0>();

        // Work in chunks of 16 bits

        let (d1, rest) = bits.split_at_mut(16);
        // 16 bits
        d1[0..=15].store_be(self.id);

        let (d2, rest) = rest.split_at_mut(16);
        // 1 bit
        d2.set(0, self.qr);
        // 4 bits
        d2[1..=4].store_be(self.opcode);
        // 1 bit
        d2.set(5, self.authoritative_answer);
        // 1 bit
        d2.set(6, self.truncation);
        // 1 bit
        d2.set(7, self.recursion_desired);
        // 1 bit
        d2.set(8, self.recursion_available);
        // 3 bits
        d2[9..=11].store_be(self.reserved);
        // 4 bits
        d2[12..=15].store_be(self.response_code);

        let (d3, rest) = rest.split_at_mut(16);
        d3.store_be(self.qd_count);

        let (d4, rest) = rest.split_at_mut(16);
        d4.store_be(self.an_count);

        let (d5, d6) = rest.split_at_mut(16);
        d5.store_be(self.ns_count);

        d6.store_be(self.ar_count);

        Bytes::copy_from_slice(&data)
    }
}
