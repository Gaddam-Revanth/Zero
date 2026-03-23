//! Shared types for the wire format.

use serde::{Deserialize, Serialize};

/// ZERO protocol version (major/minor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
}

impl Version {
    /// ZERO v1.0.
    pub const V1_0: Version = Version { major: 1, minor: 0 };
}

/// Packet types (initial registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum PacketType {
    /// ZKX Noise message 1.
    ZkxNoiseMsg1 = 0x0001,
    /// ZKX Noise message 2.
    ZkxNoiseMsg2 = 0x0002,
    /// ZKX Noise message 3.
    ZkxNoiseMsg3 = 0x0003,
    /// ZKX Init (X3DH+PQ).
    ZkxInit = 0x0004,
    /// ZR ratchet message.
    ZrMessage = 0x0010,
    /// ZDHT ping.
    ZdhtPing = 0x0020,
    /// ZDHT find record request.
    ZdhtFindRecordReq = 0x0021,
    /// ZDHT find record response.
    ZdhtFindRecordResp = 0x0022,
    /// ZSF store envelope.
    ZsfStoreEnvelope = 0x0030,
    /// ZSF fetch request.
    ZsfFetchReq = 0x0031,
    /// ZSF fetch response.
    ZsfFetchResp = 0x0032,
    /// ZGP group event.
    ZgpEvent = 0x0040,
    /// ZAV call signal.
    ZavSignal = 0x0050,
    /// ZFT file offer.
    ZftOffer = 0x0060,
    /// ZFT file chunk.
    ZftChunk = 0x0061,
    /// ZFT file ack.
    ZftAck = 0x0062,
    /// NAT hole-punching coordination.
    NatCoordination = 0x0070,
}

impl PacketType {
    /// Convert raw u16 to PacketType if known.
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x0001 => Self::ZkxNoiseMsg1,
            0x0002 => Self::ZkxNoiseMsg2,
            0x0003 => Self::ZkxNoiseMsg3,
            0x0004 => Self::ZkxInit,
            0x0010 => Self::ZrMessage,
            0x0020 => Self::ZdhtPing,
            0x0021 => Self::ZdhtFindRecordReq,
            0x0022 => Self::ZdhtFindRecordResp,
            0x0030 => Self::ZsfStoreEnvelope,
            0x0031 => Self::ZsfFetchReq,
            0x0032 => Self::ZsfFetchResp,
            0x0040 => Self::ZgpEvent,
            0x0050 => Self::ZavSignal,
            0x0060 => Self::ZftOffer,
            0x0061 => Self::ZftChunk,
            0x0062 => Self::ZftAck,
            0x0070 => Self::NatCoordination,
            _ => return None,
        })
    }
}

/// Packet flags bitfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PacketFlags(pub u16);

impl PacketFlags {
    /// sealed_sender: sender_node_id is all-zero.
    pub const SEALED_SENDER: u16 = 1 << 0;
    /// has_replay_token: body begins with replay_token (16 bytes).
    pub const HAS_REPLAY_TOKEN: u16 = 1 << 1;
    /// is_retransmit: transport hint.
    pub const IS_RETRANSMIT: u16 = 1 << 2;
    /// requires_pow: relay/storage must verify PoW.
    pub const REQUIRES_POW: u16 = 1 << 3;

    /// Bits reserved by v1.0 (must be zero).
    pub const RESERVED_MASK: u16 = 0b1111_1111_1111_0000;

    /// True if any reserved bits are set.
    pub fn has_reserved(self) -> bool {
        (self.0 & Self::RESERVED_MASK) != 0
    }

    /// Set/clear a flag.
    pub fn with(mut self, bit: u16, on: bool) -> Self {
        if on {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
        self
    }
}
