// Uncomment this block to pass the first stage
// use std::net::UdpSocket;

use std::net::UdpSocket;

use bitvec::prelude::*;
use bytes::Bytes;

fn main() {
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
                let response = Header::TEST.to_bytes();
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
}

pub struct DnsMessage(Bytes);

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
    question_code: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
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
        question_code: 0,
        answer_record_count: 0,
        authority_record_count: 0,
        additional_record_count: 0,
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
        d3.store_be(self.question_code);

        let (d4, rest) = rest.split_at_mut(16);
        d4.store_be(self.answer_record_count);

        let (d5, d6) = rest.split_at_mut(16);
        d5.store_be(self.authority_record_count);

        d6.store_be(self.additional_record_count);

        Bytes::copy_from_slice(&data)
    }
}
