//! Universal packet header and packet encoding/decoding.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{types::{PacketFlags, PacketType, Version}, WireError};

/// ASCII magic `ZERO`.
pub const MAGIC: [u8; 4] = *b"ZERO";

/// Header size in bytes for v1.0.
///
/// Layout:
/// - magic[4]
/// - version_major u16
/// - version_minor u16
/// - packet_type u16
/// - flags u16
/// - header_len u16 (must equal HEADER_LEN_V1)
/// - body_len u32
/// - padding [14]
pub const HEADER_LEN_V1: u16 = 32;

/// Maximum generic body length (1 MiB).
pub const MAX_BODY_LEN: u32 = 1_048_576;
/// Maximum handshake body length (256 KiB).
pub const MAX_HANDSHAKE_BODY_LEN: u32 = 262_144;
/// Maximum control body length (64 KiB).
pub const MAX_CONTROL_BODY_LEN: u32 = 65_535;

/// Universal packet header (v1.0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Protocol version.
    pub version: Version,
    /// Packet type.
    pub packet_type: PacketType,
    /// Flags.
    pub flags: PacketFlags,
    /// Body length (includes sender and receiver IDs in the total body parsing).
    pub body_len: u32,
}

impl PacketHeader {
    /// Validate header and enforce limits for v1.0.
    pub fn validate_v1(&self) -> Result<(), WireError> {
        if self.version.major != 1 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        if self.flags.has_reserved() {
            return Err(WireError::ReservedBitsSet);
        }
        if self.body_len > MAX_BODY_LEN {
            return Err(WireError::BodyTooLarge { got: self.body_len, max: MAX_BODY_LEN });
        }
        Ok(())
    }

    /// Encode header to bytes.
    pub fn encode_v1(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_LEN_V1 as usize);
        buf.put_slice(&MAGIC);
        buf.put_u16(self.version.major);
        buf.put_u16(self.version.minor);
        buf.put_u16(self.packet_type as u16);
        buf.put_u16(self.flags.0);
        buf.put_u16(HEADER_LEN_V1);
        buf.put_u32(self.body_len);
        buf.put_slice(&[0u8; 14]); // 14 bytes padding to equal 32 bytes
        buf.freeze()
    }

    /// Decode header from bytes (expects at least `HEADER_LEN_V1` bytes).
    pub fn decode_v1(mut b: &[u8]) -> Result<Self, WireError> {
        if b.len() < HEADER_LEN_V1 as usize {
            return Err(WireError::Truncated);
        }

        let mut magic = [0u8; 4];
        b.copy_to_slice(&mut magic);
        if magic != MAGIC {
            return Err(WireError::InvalidMagic);
        }

        let major = b.get_u16();
        let minor = b.get_u16();
        let version = Version { major, minor };

        let pt_raw = b.get_u16();
        let packet_type = PacketType::from_u16(pt_raw)
            .ok_or_else(|| WireError::UnsupportedVersion(version))?;

        let flags = PacketFlags(b.get_u16());
        let header_len = b.get_u16();
        if header_len != HEADER_LEN_V1 {
            return Err(WireError::InvalidHeaderLen { expected: HEADER_LEN_V1, got: header_len });
        }
        let body_len = b.get_u32();

        // skip 14 bytes padding
        b.advance(14);

        let hdr = PacketHeader {
            version,
            packet_type,
            flags,
            body_len,
        };
        hdr.validate_v1()?;
        Ok(hdr)
    }
}

/// A complete packet (header + dynamic routing IDs + body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// 32-byte Header.
    pub header: PacketHeader,
    /// Sender node id (all-zero when sealed sender).
    pub sender_node_id: [u8; 32],
    /// Receiver node id.
    pub receiver_node_id: [u8; 32],
    /// Body bytes.
    pub body: Bytes,
}

impl Packet {
    /// Encode packet to bytes (header + sender + receiver + body).
    pub fn encode_v1(&self) -> Result<Bytes, WireError> {
        self.header.validate_v1()?;
        if self.body.len() != self.header.body_len as usize {
            return Err(WireError::Truncated);
        }
        let total_size = HEADER_LEN_V1 as usize + 64 + self.body.len();
        let mut buf = BytesMut::with_capacity(total_size);
        buf.put_slice(&self.header.encode_v1());
        buf.put_slice(&self.sender_node_id);
        buf.put_slice(&self.receiver_node_id);
        buf.put_slice(&self.body);
        Ok(buf.freeze())
    }

    /// Decode packet from bytes.
    pub fn decode_v1(b: &[u8]) -> Result<Self, WireError> {
        let header = PacketHeader::decode_v1(b)?;
        let total = HEADER_LEN_V1 as usize + 64 + header.body_len as usize;
        if b.len() < total {
            return Err(WireError::Truncated);
        }
        
        // Extract routing IDs
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&b[HEADER_LEN_V1 as usize .. HEADER_LEN_V1 as usize + 32]);
        let mut receiver = [0u8; 32];
        receiver.copy_from_slice(&b[HEADER_LEN_V1 as usize + 32 .. HEADER_LEN_V1 as usize + 64]);
        
        let body = Bytes::copy_from_slice(&b[HEADER_LEN_V1 as usize + 64 .. total]);
        Ok(Packet { header, sender_node_id: sender, receiver_node_id: receiver, body })
    }
}

