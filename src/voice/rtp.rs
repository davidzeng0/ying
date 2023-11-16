use pnet_macros::packet;
use pnet_macros_support::types::*;

#[packet]
pub struct ExtensionHeader {
	pub profile: u16be,
	pub length: u16be,

	#[payload]
	#[length = "0"]
	_payload: Vec<u8>
}

#[packet]
pub struct Rtp {
	pub version: u2,
	pub padding: u1,
	pub extension: u1,
	pub csrc_count: u4,
	pub marker: u1,
	pub packet_type: u7,
	pub sequence: u16be,
	pub timestamp: u32be,
	pub ssrc: u32be,

	#[length = "extension * 4"]
	pub extension_header: Vec<ExtensionHeader>,

	#[length = "csrc_count * 4"]
	pub csrcs: Vec<u32be>,

	#[payload]
	pub payload: Vec<u8>
}

#[packet]
pub struct Rtcp {
	pub version: u2,
	pub padding: u1,
	pub report_count: u5,
	pub packet_type: u8,
	pub length: u16be,
	pub ssrc: u32be,

	#[payload]
	pub payload: Vec<u8>
}

#[packet]
pub struct SenderInfo {
	pub ntp_timestamp: u64be,
	pub rtp_timestamp: u32be,
	pub sender_packets: u32be,
	pub sender_octets: u32be,

	#[payload]
	pub reports: Vec<u8>
}

#[packet]
pub struct Report {
	pub ssrc: u32be,
	pub fraction_lost: u8,
	pub cumulative_lost: u24be,
	pub highest_sequence: u32be,
	pub interarrival_jitter: u32be,
	pub last_sender_report: u32be,
	pub delay_since_last_sender_report: u32be,

	#[payload]
	#[length = "0"]
	_payload: Vec<u8>
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum ExtensionProfile {
	OneByte  = 0xbede,
	TwoBytes = 0x1000
}

pub struct ExtensionIterator<'a> {
	profile: u16,
	buf: &'a [u8],
	index: usize
}

impl<'a> ExtensionIterator<'a> {
	pub fn new(profile: u16, buf: &'a [u8]) -> Self {
		Self { profile, buf, index: 0 }
	}

	fn next_one_byte(&mut self) -> Option<<Self as Iterator>::Item> {
		loop {
			if self.index >= self.buf.len() {
				break None;
			}

			let ext = self.buf[self.index];

			self.index += 1;

			if ext == 0 {
				continue;
			}

			let id = ext >> 4;
			let len = (ext as usize & 0xf) + 1;

			if self.index + len > self.buf.len() {
				self.index = self.buf.len();

				break None;
			}

			let buf = &self.buf[self.index..self.index + len];

			self.index += len;

			break Some((id, buf));
		}
	}
}

impl<'a> Iterator for ExtensionIterator<'a> {
	type Item = (u8, &'a [u8]);

	fn next(&mut self) -> Option<Self::Item> {
		if self.profile == ExtensionProfile::OneByte as u16 {
			self.next_one_byte()
		} else {
			None
		}
	}
}
