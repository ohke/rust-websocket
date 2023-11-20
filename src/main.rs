use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread::sleep,
    time::Duration,
};

pub fn echo(payload: &[u8]) -> Vec<u8> {
    return payload.to_vec();
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7778").unwrap();
    let mut buffer = [0; 4096];

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut is_websocket = false;

        loop {
            if let Err(_) = stream.read(&mut buffer) {
                break;
            }

            if is_websocket {
                println!("WebSocket");

                let frame = Frame::from(&buffer[..]);

                if frame.opcode == Opcode::Close {
                    println!("Close");

                    let response = Frame::new(Opcode::Close, false, None);

                    stream.write(&response.to_bytes()).unwrap();
                    stream.flush().unwrap();

                    break;
                } else if frame.opcode == Opcode::Ping {
                    println!("Ping");

                    let response = Frame::new(Opcode::Pong, false, Some(frame.payload_data));

                    stream.write(&response.to_bytes()).unwrap();
                    stream.flush().unwrap();
                } else if frame.opcode == Opcode::Text {
                    println!("Text");

                    let payload_data = echo(frame.payload_data.as_slice());
                    let response: Frame = Frame::new(Opcode::Text, false, Some(payload_data));

                    stream.write(&response.clone().to_bytes()).unwrap();
                    stream.flush().unwrap();

                    // 3秒後に同じペイロードで送信
                    sleep(Duration::from_secs(3));

                    stream.write(&response.to_bytes()).unwrap();
                    stream.flush().unwrap();
                } else {
                    todo!();
                }
            } else {
                println!("HTTP");

                // リクエストのパース
                let mut method = None;
                let mut upgrade = None;
                let mut connection = None;
                let mut sec_websocket_version = None;
                let mut sec_websocket_key = None;

                let request_text = String::from_utf8_lossy(&buffer[..]);
                for (i, line) in request_text.lines().enumerate() {
                    if i == 0 {
                        let values = line.split(" ").map(|s| s.trim()).collect::<Vec<&str>>();
                        method = Some(values[0].to_ascii_lowercase());
                        continue;
                    }

                    if line == "" {
                        break;
                    }

                    let values = line.split(":").map(|s| s.trim()).collect::<Vec<&str>>();
                    let key = values[0].to_ascii_lowercase();
                    let value = values[1];
                    if key == "host" {
                        println!("host: {}", value);
                    }
                    if key == "upgrade" {
                        upgrade = Some(value.to_ascii_lowercase());
                    }
                    if key == "connection" {
                        connection = Some(value.to_ascii_lowercase());
                    }
                    if key == "sec-websocket-version" {
                        sec_websocket_version = Some(value);
                    }
                    if key == "sec-websocket-key" {
                        sec_websocket_key = Some(value);
                    }
                }

                if !(method.map_or(false, |v| v == "get")
                    && upgrade.map_or(false, |v| v == "websocket")
                    && connection.map_or(false, |v| v == "upgrade")
                    && sec_websocket_version.map_or(false, |v| v == "13")
                    && sec_websocket_key.is_some())
                {
                    println!("Illegal request.");
                    continue;
                }

                // レスポンスの作成と送信
                // ex. 0CBldYnlIlaeSy6juzli7g== => 6mUsN+jbuye0zMbRm4w9VfzxDGM=
                let plain_text = format!(
                    "{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
                    sec_websocket_key.unwrap()
                );
                let mut hasher = Sha1::new();
                hasher.update(plain_text);
                let sec_websocket_accept = general_purpose::STANDARD.encode(hasher.finalize());

                let response = format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", sec_websocket_accept);
                stream.write(response.as_bytes()).unwrap();
                stream.flush().unwrap();

                is_websocket = true;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Opcode {
    Continuation, // %x0
    Text,         // %x1
    Binary,       // %x2
    Close,        // %x8
    Ping,         // %x9
    Pong,         // %xA
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        match byte & 0x0F {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            _ => panic!("Invalid opcode"),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        match opcode {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+
#[derive(Clone, Debug)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: Opcode,
    pub mask: bool,
    pub payload_len: usize, // included extended payload length
    pub masking_key: Option<[u8; 4]>,
    pub payload_data: Vec<u8>, // decoded (with masking_key)
}

impl Frame {
    pub fn new(opcode: Opcode, mask: bool, payload_data: Option<Vec<u8>>) -> Self {
        let masking_key = if mask {
            let mut rng = rand::thread_rng();
            let mut masking_key = [0; 4];
            rng.fill(&mut masking_key);
            Some(masking_key)
        } else {
            None
        };

        let (payload_len, payload_data) = match (payload_data, masking_key) {
            (Some(mut payload_data), Some(maskig_key)) => {
                for (i, b) in payload_data.iter_mut().enumerate() {
                    *b ^= maskig_key[i % 4];
                }
                (payload_data.len(), payload_data)
            }
            (Some(payload_data), None) => (payload_data.len(), payload_data),
            (None, _) => (0, vec![]),
        };

        Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            mask,
            payload_len,
            masking_key,
            payload_data,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.push(
            (self.fin as u8) << 7
                | (self.rsv1 as u8) << 6
                | (self.rsv2 as u8) << 5
                | (self.rsv3 as u8) << 4
                | u8::from(self.opcode),
        );

        if self.payload_len < 126 {
            buffer.push((self.mask as u8) << 7 | self.payload_len as u8)
        } else if self.payload_len < 65536 {
            buffer.push((self.mask as u8) << 7 | 126_u8);
            buffer.extend_from_slice((self.payload_len as u16).to_be_bytes().as_ref());
        } else {
            buffer.push((self.mask as u8) << 7 | 127_u8);
            buffer.extend_from_slice((self.payload_len as u64).to_be_bytes().as_ref());
        }

        if self.mask {
            buffer.extend(self.masking_key.unwrap().clone());
        }

        for (i, b) in self.payload_data.iter().enumerate() {
            buffer.push(if self.mask {
                b ^ self.masking_key.unwrap()[i % 4]
            } else {
                *b
            });
        }

        return buffer;
    }
}

impl From<&[u8]> for Frame {
    fn from(buffer: &[u8]) -> Self {
        let fin = buffer[0] & 0x80 != 0x00;
        let rsv1 = buffer[0] & 0x40 != 0x00;
        let rsv2 = buffer[0] & 0x20 != 0x00;
        let rsv3 = buffer[0] & 0x10 != 0x00;
        let opcode = Opcode::from(buffer[0]);

        let mask = buffer[1] & 0x80 != 0;

        let (payload_len, mut i) = match buffer[1] & 0x7F {
            0x7E => {
                let mut payload_len = [0; 2];
                payload_len.copy_from_slice(&buffer[2..4]);
                (u16::from_be_bytes(payload_len) as usize, 4)
            }
            0x7F => {
                let mut payload_len = [0; 8];
                payload_len.copy_from_slice(&buffer[2..10]);
                (usize::from_be_bytes(payload_len), 10)
            }
            n => (n as usize, 2),
        };
        let masking_key = if mask {
            let mut masking_key = [0; 4];
            masking_key.copy_from_slice(&buffer[i..i + 4]);
            i += 4;
            Some(masking_key)
        } else {
            None
        };
        let payload_data: Vec<u8> = if mask {
            buffer[i..i + payload_len]
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ masking_key.unwrap()[i % 4])
                .collect()
        } else {
            buffer[i..i + payload_len].to_vec()
        };

        Frame {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            mask,
            payload_len,
            masking_key,
            payload_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_new_text_data() {
        let frame = Frame::new(Opcode::Text, false, Some(vec![0x4f, 0x4b]));
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.mask, false);
        assert_eq!(frame.payload_len, 2);
        assert_eq!(frame.masking_key, None);
        assert_eq!(frame.payload_data, vec![0x4f, 0x4b]);
    }

    #[test]
    fn test_frame_new_masking_text_data() {
        let frame = Frame::new(
            Opcode::Text,
            true,
            Some(vec![0x4f, 0x4b, 0x4f, 0x4b, 0x4f, 0x4b]),
        );
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.mask, true);
        assert_eq!(frame.payload_len, 6);
        let m = frame.masking_key.unwrap();
        assert_eq!(
            frame.payload_data,
            vec![
                0x4f ^ m[0],
                0x4b ^ m[1],
                0x4f ^ m[2],
                0x4b ^ m[3],
                0x4f ^ m[0],
                0x4b ^ m[1]
            ]
        );
    }

    #[test]
    fn test_frame_from_text_data() {
        let buffer = [
            0b10000001, // fin, rsv1, rsv2, rsv3, opcode
            0b00000010, // mask, payload_len
            0x4f, 0x4b, // OK
        ];
        let frame = Frame::from(&buffer[..]);
        assert_eq!(frame.fin, true);
        assert_eq!(frame.rsv1, false);
        assert_eq!(frame.rsv2, false);
        assert_eq!(frame.rsv3, false);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.mask, false);
        assert_eq!(frame.payload_len, 2);
        assert_eq!(frame.masking_key, None);
        assert_eq!(frame.payload_data, vec![0x4f, 0x4b]);
    }

    #[test]
    fn test_frame_from_masking_text_data() {
        let buffer = [
            0b10000001, // fin, rsv1, rsv2, rsv3, opcode
            0b10000100, // mask, payload_len
            0b00000000, 0b01001011, 0b01010101, 0b10101010, // masking_key
            0b01001111, 0b00000000, 0b00011010, 0b11100001, // OKOK
        ];
        let frame = Frame::from(&buffer[..]);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.mask, true);
        assert_eq!(
            frame.masking_key,
            Some([0b00000000, 0b01001011, 0b01010101, 0b10101010])
        );
        assert_eq!(frame.payload_data, vec![0x4f, 0x4b, 0x4f, 0x4b]);
    }

    #[test]
    fn test_frame_from_medium_text_data() {
        let data: Vec<u8> = (0..256).map(|_| 0x40).collect();

        let mut buffer = [
            0b10000001, // fin, rsv1, rsv2, rsv3, opcode
            0b01111110, // mask, payload_len (extended)
            0x01, 0x00, // payload_len (256)
        ]
        .to_vec();
        buffer.append(&mut data.clone());

        let frame = Frame::from(&buffer[..]);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload_len, 256);
        assert_eq!(frame.payload_data, data);
    }

    #[test]
    fn test_frame_to_bytes_text_data() {
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            mask: false,
            payload_len: 2,
            masking_key: None,
            payload_data: vec![0x4f, 0x4b],
        };
        let buffer = frame.to_bytes();
        assert_eq!(buffer, vec![0b10000001, 0b00000010, 0x4f, 0x4b]);
    }

    #[test]
    fn test_frame_to_bytes_masking_text_data() {
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            mask: true,
            payload_len: 6,
            masking_key: Some([0b00000000, 0b01001011, 0b01010101, 0b10101010]),
            payload_data: vec![0x4f, 0x4b, 0x4f, 0x4b, 0x4f, 0x4b],
        };

        let buffer = frame.to_bytes();
        assert_eq!(
            buffer,
            vec![
                // header
                0b10000001, 0b10000110, 0b00000000, 0b01001011, 0b01010101, 0b10101010,
                // data
                0b01001111, 0b00000000, 0b00011010, 0b11100001, 0b01001111, 0b00000000,
            ]
        );
    }

    #[test]
    fn test_frame_to_bytes_medium_text_data() {
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            mask: false,
            payload_len: 256,
            masking_key: None,
            payload_data: (0..256).map(|_| 0x40).collect(),
        };

        let buffer = frame.to_bytes();

        let mut expected = vec![
            // header
            0b10000001, 0b01111110, 0x01, 0x00,
        ];
        expected.append(&mut (0..256).map(|_| 0x40).collect::<Vec<u8>>());

        assert_eq!(buffer, expected);
    }
}
