// Uncomment this block to pass the first stage
// use std::net::UdpSocket;

use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use bitvec::prelude::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::random;

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let resolver = std::env::args()
        .nth(2)
        .map(|s| SocketAddrV4::from_str(&s))
        .transpose()?;

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0u8; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let mut received_data = Bytes::copy_from_slice(&buf[..size]);
                println!("Received {} bytes from {}", size, source);
                let msg_in = DnsMessage::from_bytes(&mut received_data)?;

                let mut questions = Vec::new();
                let mut answers = Vec::new();

                if let Some(resolver) = resolver {
                    for q in &msg_in.questions {
                        let response = resolve(resolver, q.clone())?;
                        if !response.answers.is_empty() {
                            questions.push(q.clone());
                            answers.push(response.answers[0].clone());
                        }
                    }
                } else {
                    for question in &msg_in.questions {
                        questions.push(question.clone());
                        answers.push(ResourceRecord::a_in(
                            question.qname.clone(),
                            60,
                            "8.8.8.8".parse()?,
                        ))
                    }
                }
                let msg_out = DnsMessage {
                    header: Header {
                        id: msg_in.header.id,
                        qr: true, // response
                        opcode: msg_in.header.opcode,
                        authoritative_answer: false,
                        truncation: false,
                        recursion_desired: msg_in.header.recursion_desired,
                        recursion_available: false,
                        reserved: 0,
                        response_code: if msg_in.header.opcode == 0 { 0 } else { 4 },
                        qd_count: questions.len() as u16,
                        an_count: answers.len() as u16,
                        ..Default::default()
                    },
                    questions,
                    answers,
                };
                let response = msg_out.to_bytes();
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

#[derive(Debug, Clone)]
pub struct DnsMessage {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
}

impl DnsMessage {
    pub fn from_bytes(bytes: &mut Bytes) -> Result<Self> {
        // Keep a reference to the whole so we can resolve label pointers
        let payload = bytes.clone();

        let header = Header::from_bytes(bytes)?;
        let mut questions = Vec::new();

        for _ in 0..header.qd_count {
            let mut q = Question::from_bytes(bytes)?;
            q.resolve_labels(&payload);
            questions.push(q);
        }

        let mut answers = Vec::new();
        for _ in 0..header.an_count {
            let a = ResourceRecord::from_bytes(bytes)?;
            answers.push(a);
        }

        Ok(Self {
            header,
            questions,
            answers,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put(self.header.to_bytes());
        for q in &self.questions {
            buf.put(q.to_bytes());
        }
        for a in &self.answers {
            buf.put(a.to_bytes());
        }

        buf.freeze()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    qname: QName,
    // qtype: QType,
    // qclass: QClass,
    qtype: u16,
    qclass: u16,
}

impl Question {
    pub fn from_bytes(bytes: &mut Bytes) -> Result<Self> {
        let qname = QName::from_bytes(bytes)?;
        // let qtype = QType::try_from(bytes.get_u16())?;
        // let qclass = QClass::try_from(bytes.get_u16())?;
        let qtype = bytes.get_u16();
        let qclass = bytes.get_u16();

        Ok(Self {
            qname,
            qtype,
            qclass,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put(self.qname.to_bytes());
        buf.put_u16(self.qtype);
        buf.put_u16(self.qclass);

        buf.freeze()
    }

    pub fn resolve_labels(&mut self, payload: &Bytes) {
        self.qname.0.iter_mut().for_each(|label| {
            if let Label::Ptr(offset) = label {
                *label = Label::from_bytes(&mut payload.slice((*offset as usize)..))
                    .expect("No label found in payload at offset {offset}!")
            }
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QName(Vec<Label>);

impl QName {
    pub fn from_bytes(bytes: &mut Bytes) -> Result<Self> {
        let mut labels = Vec::new();
        while let Some(label) = Label::from_bytes(bytes) {
            let is_ptr = label.is_ptr();
            labels.push(label);

            if is_ptr {
                break;
            }
        }

        Ok(Self(labels))
    }

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
            .map(|label| Label::Full(Bytes::copy_from_slice(label.as_bytes())))
            .collect();
        Ok(Self(labels))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label {
    Ptr(u16),
    Full(Bytes),
}

impl Label {
    const PTR_MASK: u8 = 0b11000000;

    pub fn from_bytes(bytes: &mut Bytes) -> Option<Self> {
        let len = bytes.get_u8();
        if len == 0 {
            None
        } else if len & Self::PTR_MASK != 0 {
            let n = bytes.get_u8();
            let mut offset = 0_u16;
            offset |= ((len & !Self::PTR_MASK) as u16) << 8;
            offset |= n as u16;
            Some(Self::Ptr(offset))
        } else {
            let data = bytes.copy_to_bytes(len as usize);
            Some(Self::Full(data))
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            Label::Ptr(offset) => buf.put_u16(offset | ((Self::PTR_MASK as u16) << 8)),
            Label::Full(data) => {
                buf.put_u8(data.len() as u8);
                buf.put(data.slice(..));
            }
        }

        buf.freeze()
    }

    pub fn is_ptr(&self) -> bool {
        match self {
            Label::Ptr(_) => true,
            Label::Full(_) => false,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum QType {
    #[default]
    UNKNOWN = 0, // Shouldn't be here, but the tester sometimes sends this...
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

impl TryFrom<u16> for QType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UNKNOWN),
            1 => Ok(Self::A),
            _ => bail!("Not implemented or invalid! {value}"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum QClass {
    #[default]
    UNKNOWN = 0, // Shouldn't be here but the tester sometimes sends this...
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
}

impl TryFrom<u16> for QClass {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UNKNOWN),
            1 => Ok(Self::IN),
            _ => bail!("Not implemented or invalid! {value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    qname: QName,
    r#type: u16,
    class: u16,
    ttl: u32,
    rd_length: u16,
    rd_data: Bytes,
}

impl ResourceRecord {
    pub fn a_in(qname: QName, ttl: u32, addr: Ipv4Addr) -> Self {
        Self {
            qname,
            r#type: QType::A as u16,
            class: QClass::IN as u16,
            ttl,
            rd_length: 4,
            rd_data: Bytes::copy_from_slice(addr.octets().as_slice()),
        }
    }

    pub fn from_bytes(bytes: &mut Bytes) -> anyhow::Result<Self> {
        let qname = QName::from_bytes(bytes)?;
        let r#type = bytes.get_u16();
        let class = bytes.get_u16();
        let ttl = bytes.get_u32();
        let rd_length = bytes.get_u16();
        let rd_data = bytes.copy_to_bytes(rd_length as usize);

        Ok(Self {
            qname,
            r#type,
            class,
            ttl,
            rd_length,
            rd_data,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put(self.qname.to_bytes());
        buf.put_u16(self.r#type);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);
        buf.put_u16(self.rd_length);
        buf.put(self.rd_data.clone());

        buf.freeze()
    }
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
    pub fn from_bytes(bytes: &mut Bytes) -> anyhow::Result<Self> {
        let id = bytes.get_u16();

        let d = bytes.get_u16();
        let bits = d.view_bits::<Msb0>();
        let qr = bits[0];
        let opcode: u8 = bits[1..=4].load_be();
        let authoritative_answer = bits[5];
        let truncation = bits[6];
        let recursion_desired = bits[7];
        let recursion_available = bits[8];
        let reserved = bits[9..=11].load_be();
        let response_code = bits[12..=15].load_be();

        let qd_count = bytes.get_u16();
        let an_count = bytes.get_u16();
        let ns_count = bytes.get_u16();
        let ar_count = bytes.get_u16();

        Ok(Self {
            id,
            qr,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            reserved,
            response_code,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    }

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

pub fn resolve(resolver: SocketAddrV4, q: Question) -> anyhow::Result<DnsMessage> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket")?;
    let id = random::<u16>();

    let msg = DnsMessage {
        header: Header {
            id,
            qd_count: 1,
            ..Default::default()
        },
        questions: vec![q],
        answers: vec![],
    };
    println!("Sending msg to resolver: {msg:?}");
    let bytes = msg.to_bytes();

    let _ = socket
        .send_to(&bytes, resolver)
        .context("Failed to send message to resolver")?;
    let mut buf = [0u8; 512];
    // wait for response
    loop {
        let size = socket.recv(&mut buf).context("Failed to read UDP packet")?;
        let mut received_data = Bytes::copy_from_slice(&buf[..size]);
        let resp =
            DnsMessage::from_bytes(&mut received_data).context("Failed to parse DNS message")?;
        if resp.header.id != id {
            println!("Got DNS message with wrong id. Ignoring...");
            continue;
        } else {
            println!("Got response from resolver: {resp:?}");
            return Ok(resp);
        }
    }
}
