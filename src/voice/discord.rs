use std::{
	net::{IpAddr, SocketAddr},
	str::from_utf8
};

use enumflags2::bitflags;
use num_derive::FromPrimitive;
use pnet_macros::packet;
use pnet_macros_support::types::*;

use super::*;

#[repr(u16)]
pub enum IpDiscoveryType {
	Request  = 0x1,
	Response = 0x2
}

#[packet]
pub struct IpDiscovery {
	pub ty: u16be,
	pub length: u16be,
	pub ssrc: u32be,
	#[length = "length - 6"]
	pub ip: Vec<u8>,
	pub port: u16be,

	#[payload]
	#[length = "0"]
	pub payload: Vec<u8>
}

impl IpDiscovery {
	pub fn new(ssrc: u32) -> [u8; 74] {
		let mut payload = [0u8; IpDiscoveryPacket::minimum_packet_size() + 64];
		let mut packet = MutableIpDiscoveryPacket::new(&mut payload).unwrap();

		packet.set_ty(IpDiscoveryType::Request as u16);
		packet.set_ssrc(ssrc);
		packet.set_length(70);
		payload
	}

	pub fn parse(buf: &[u8]) -> Option<(u32, SocketAddr)> {
		let packet = IpDiscoveryPacket::new(&buf)?;

		if packet.get_ty() != IpDiscoveryType::Response as u16 {
			return None;
		}

		let index = packet.get_ip_raw().iter().position(|b| *b == 0)?;
		let ip = from_utf8(&packet.get_ip_raw()[0..index])
			.ok()?
			.parse::<IpAddr>()
			.ok()?;
		let addr = SocketAddr::new(ip, packet.get_port());

		Some((packet.get_ssrc(), addr))
	}
}

/// RTC heartbeating
#[packet]
pub struct KeepAlive {
	pub prefix: u32be,
	pub nonce: u32be,

	#[payload]
	#[length = "0"]
	pub payload: Vec<u8>
}

impl KeepAlive {
	/// Maximum outstanding keepalives before closing the connection
	pub const MAX: usize = 12;
	/// Leet!
	pub const PREFIX: u32 = 0x1337cafe;
}

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromPrimitive)]
pub enum ExtensionId {
	AudioLevel    = 1,
	SpeakingFlags = 9
}

/// The speaking flags, when received via RTP extensions
#[bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpeakingFlag {
	Priority   = 1 << 0,
	Microphone = 1 << 1,
	Soundshare = 1 << 2
}

/// Discord voice servers don't accept any packets that exceed the ethernet MTU
/// So we shouldn't expect to receive any packets larger than this either
///
/// The UDP and IP headers are not subtracted from this number
pub const MAX_PACKET_SIZE: usize = 1500;

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum PayloadType {
	Av1            = 101,
	Av1Rtx         = 102,
	H264           = 103,
	H264Rtx        = 104,
	Vp8            = 105,
	Vp8Rtx         = 106,
	Vp9            = 107,
	Vp9Rtx         = 108,
	Opus           = 120,
	SenderReport   = 200,
	ReceiverReport = 201
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionMode {
	None = 0,
	XSalsa20Poly1305,
	XSalsa20Poly1305Suffix,
	XSalsa20Poly1305Lite,
	XSalsa20Poly1305LiteRtpSize,
	AeadAes256Gcm,
	AeadAes256GcmRtpSize,
	AeadXChaCha20Poly1305RtpSize
}

impl EncryptionMode {
	pub fn to_str(&self) -> &'static str {
		use EncryptionMode::*;

		match self {
			None => "none",
			XSalsa20Poly1305 => "xsalsa20_poly1305",
			XSalsa20Poly1305Suffix => "xsalsa20_poly1305_suffix",
			XSalsa20Poly1305Lite => "xsalsa20_poly1305_lite",
			XSalsa20Poly1305LiteRtpSize => "xsalsa20_poly1305_lite_rtpsize",
			AeadAes256Gcm => "aead_aes256_gcm",
			AeadAes256GcmRtpSize => "aead_aes256_gcm_rtpsize",
			AeadXChaCha20Poly1305RtpSize => "aead_xchacha20_poly1305_rtpsize"
		}
	}

	pub fn from_str(str: &str) -> Option<EncryptionMode> {
		use EncryptionMode::*;

		Some(match str {
			"xsalsa20_poly1305" => XSalsa20Poly1305,
			"xsalsa20_poly1305_suffix" => XSalsa20Poly1305Suffix,
			"xsalsa20_poly1305_lite" => XSalsa20Poly1305Lite,
			"xsalsa20_poly1305_lite_rtpsize" => XSalsa20Poly1305LiteRtpSize,
			"aead_aes256_gcm" => AeadAes256Gcm,
			"aead_aes256_gcm_rtpsize" => AeadAes256GcmRtpSize,
			"aead_xchacha20_poly1305_rtpsize" => AeadXChaCha20Poly1305RtpSize,
			_ => return Option::None
		})
	}

	pub fn rtcp_aead_len(&self) -> usize {
		use EncryptionMode::*;

		match self {
			None => 0,
			_ => RtcpPacket::minimum_packet_size()
		}
	}

	pub fn rtp_aead_len(&self, packet: &RtpPacket) -> usize {
		use EncryptionMode::*;

		let len = RtpPacket::minimum_packet_size();

		match self {
			None => 0,
			XSalsa20Poly1305 | XSalsa20Poly1305Suffix | XSalsa20Poly1305Lite | AeadAes256Gcm => len,
			_ => len + packet.get_extension_header_raw().len() + packet.get_csrcs_raw().len()
		}
	}

	/// Returns the length in bytes of the trailing nonce data in the packet
	pub fn nonce_size(&self) -> usize {
		use EncryptionMode::*;

		match self {
			None | XSalsa20Poly1305 => 0,
			XSalsa20Poly1305Suffix => 24,
			_ => 4
		}
	}
}
