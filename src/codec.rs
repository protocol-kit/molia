//! Fixed 12-byte header + Protobuf body. UDP provides framing.

use crate::proto;
use crate::types::{HEADER_LEN, PMTU_FLOOR, PROTOCOL_VERSION};
use prost::Message;

pub const FLAG_RESPONSE: u8 = 1 << 0;
pub const FLAG_MORE_CHUNKS: u8 = 1 << 1;
pub const FLAG_PROBE: u8 = 1 << 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Ping = 1,
    Pong = 2,
    NegotiateReq = 3,
    NegotiateResp = 4,
    FindNodeReq = 5,
    FindNodeResp = 6,
    FindValueReq = 7,
    FindValueResp = 8,
    StoreReq = 9,
    StoreResp = 10,
    AnnounceProviderReq = 11,
    AnnounceProviderResp = 12,
    Punch = 13,
    Relay = 14,
    TraceHint = 250,
    CacheHint = 251,
    Error = 255,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Ping,
            2 => Self::Pong,
            3 => Self::NegotiateReq,
            4 => Self::NegotiateResp,
            5 => Self::FindNodeReq,
            6 => Self::FindNodeResp,
            7 => Self::FindValueReq,
            8 => Self::FindValueResp,
            9 => Self::StoreReq,
            10 => Self::StoreResp,
            11 => Self::AnnounceProviderReq,
            12 => Self::AnnounceProviderResp,
            13 => Self::Punch,
            14 => Self::Relay,
            250 => Self::TraceHint,
            251 => Self::CacheHint,
            255 => Self::Error,
            _ => return None,
        })
    }

    pub fn is_request(self) -> bool {
        matches!(
            self,
            Self::Ping
                | Self::NegotiateReq
                | Self::FindNodeReq
                | Self::FindValueReq
                | Self::StoreReq
                | Self::AnnounceProviderReq
                | Self::Punch
                | Self::Relay
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Qos {
    Control = 0,
    Coordination = 1,
    Hints = 2,
}

impl Qos {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Control,
            1 => Self::Coordination,
            _ => Self::Hints,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub version: u8,
    pub ty: MessageType,
    pub flags: u8,
    pub qos: Qos,
    pub correlation: u32,
    pub stream_id: u32,
}

impl Header {
    pub fn request(ty: MessageType, qos: Qos, correlation: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ty,
            flags: 0,
            qos,
            correlation,
            stream_id: 0,
        }
    }

    pub fn response(ty: MessageType, qos: Qos, correlation: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ty,
            flags: FLAG_RESPONSE,
            qos,
            correlation,
            stream_id: 0,
        }
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    pub fn is_probe(&self) -> bool {
        self.flags & FLAG_PROBE != 0
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < HEADER_LEN {
            return None;
        }
        out[0] = self.version;
        out[1] = self.ty as u8;
        out[2] = self.flags;
        out[3] = self.qos as u8;
        out[4..8].copy_from_slice(&self.correlation.to_be_bytes());
        out[8..12].copy_from_slice(&self.stream_id.to_be_bytes());
        Some(HEADER_LEN)
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        if buf[0] != PROTOCOL_VERSION {
            return None;
        }
        let ty = MessageType::from_u8(buf[1])?;
        Some(Self {
            version: buf[0],
            ty,
            flags: buf[2],
            qos: Qos::from_u8(buf[3]),
            correlation: u32::from_be_bytes(buf[4..8].try_into().ok()?),
            stream_id: u32::from_be_bytes(buf[8..12].try_into().ok()?),
        })
    }
}

pub fn encode_message(header: &Header, body: &impl Message, out: &mut [u8]) -> Option<usize> {
    let n = header.encode(out)?;
    let body_len = body.encoded_len();
    if n + body_len > out.len() || n + body_len > PMTU_FLOOR {
        return None;
    }
    body.encode(&mut &mut out[n..n + body_len]).ok()?;
    Some(n + body_len)
}

pub fn decode_body<T: Message + Default>(buf: &[u8]) -> Option<T> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    T::decode(&buf[HEADER_LEN..]).ok()
}

pub fn encode_ping(correlation: u32, now_unix_ms: u64, out: &mut [u8]) -> Option<usize> {
    encode_message(
        &Header::request(MessageType::Ping, Qos::Control, correlation),
        &proto::Ping {
            now_unix_ms,
            ..Default::default()
        },
        out,
    )
}

pub fn encode_pong(correlation: u32, now_unix_ms: u64, out: &mut [u8]) -> Option<usize> {
    encode_message(
        &Header::response(MessageType::Pong, Qos::Control, correlation),
        &proto::Pong {
            now_unix_ms,
            ..Default::default()
        },
        out,
    )
}

pub fn default_capabilities() -> proto::Capabilities {
    proto::Capabilities {
        version: 1,
        bitmap: FEATURE_DEFAULT,
        max_msg_bytes: PMTU_FLOOR as u32,
    }
}

const FEATURE_DEFAULT: u64 = crate::types::FEATURE_PRIVACY_BLINDING | crate::types::FEATURE_ERASURE_HINTS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header::request(MessageType::FindNodeReq, Qos::Coordination, 0xAABBCCDD);
        let mut buf = [0u8; 12];
        assert_eq!(h.encode(&mut buf), Some(12));
        let d = Header::decode(&buf).unwrap();
        assert_eq!(d.ty, MessageType::FindNodeReq);
        assert_eq!(d.correlation, 0xAABBCCDD);
        assert!(!d.is_response());
    }

    #[test]
    fn ping_pong_encode() {
        let mut buf = [0u8; 64];
        let n = encode_ping(7, 1234, &mut buf).unwrap();
        let h = Header::decode(&buf[..n]).unwrap();
        let p = decode_body::<proto::Ping>(&buf[..n]).unwrap();
        assert_eq!(h.ty, MessageType::Ping);
        assert_eq!(p.now_unix_ms, 1234);
    }

    #[test]
    fn unknown_type_is_none() {
        let mut buf = [0u8; 12];
        buf[0] = PROTOCOL_VERSION;
        buf[1] = 99;
        assert!(Header::decode(&buf).is_none());
    }
}
