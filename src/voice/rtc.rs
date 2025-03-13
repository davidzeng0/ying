use std::{
	fmt,
	mem::{size_of, transmute, MaybeUninit},
	net::{IpAddr, SocketAddr},
	time::Duration
};

use enumflags2::BitFlags;
use num_traits::FromPrimitive;
use pnet_macros_support::packet::Packet as _;
use xx_core::{
	error::*,
	os::{
		inet::AddressStorage,
		iovec::IoVec,
		socket::{MessageFlag, MessageHeader}
	},
	pointer::MutPtr,
	trace
};
use xx_pulse::*;

use super::{discord::SpeakingFlag, *};

fn parse_reports(report_count: usize, buf: &[u8]) -> Option<Vec<Report>> {
	let size = ReportPacket::minimum_packet_size();

	if report_count * size != buf.len() {
		return None;
	}

	let mut reports = Vec::new();

	for i in 0..report_count {
		let report = ReportPacket::new(&buf[i * size..]).unwrap();

		reports.push(Report {
			ssrc: report.get_ssrc(),
			fraction_lost: report.get_fraction_lost(),
			cumulative_lost: report.get_cumulative_lost(),
			highest_sequence: report.get_highest_sequence(),
			interarrival_jitter: report.get_interarrival_jitter(),
			last_sender_report: report.get_last_sender_report(),
			delay_since_last_sender_report: report.get_delay_since_last_sender_report()
		});
	}

	Some(reports)
}

#[derive(Debug, Clone)]
pub struct Report {
	pub ssrc: u32,
	pub fraction_lost: u8,
	pub cumulative_lost: u32,
	pub highest_sequence: u32,
	pub interarrival_jitter: u32,
	pub last_sender_report: u32,
	pub delay_since_last_sender_report: u32
}

#[derive(Debug, Clone)]
pub struct SenderReport {
	pub ntp_timestamp: u64,
	pub rtp_timestamp: u32,
	pub sender_packets: u32,
	pub sender_octets: u32,
	pub reports: Vec<Report>
}

impl SenderReport {
	pub fn parse(buf: &[u8]) -> Option<SenderReport> {
		let packet = RtcpPacket::new(buf)?;
		let info = SenderInfoPacket::new(packet.payload())?;

		Some(SenderReport {
			ntp_timestamp: info.get_ntp_timestamp(),
			rtp_timestamp: info.get_rtp_timestamp(),
			sender_packets: info.get_sender_packets(),
			sender_octets: info.get_sender_octets(),
			reports: parse_reports(packet.get_report_count() as usize, info.payload())?
		})
	}
}

#[derive(Debug, Clone)]
pub struct ReceiverReport {
	pub reports: Vec<Report>
}

impl ReceiverReport {
	pub fn parse(buf: &[u8]) -> Option<ReceiverReport> {
		let packet = RtcpPacket::new(buf)?;

		Some(ReceiverReport {
			reports: parse_reports(packet.get_report_count() as usize, packet.payload())?
		})
	}
}

pub enum Packet {
	KeepAlive(u32),
	Opus(Opus),
	SenderReport(SenderReport),
	ReceiverReport(ReceiverReport)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RtpType {
	Rtp(u32),
	Rtcp(u32)
}

impl From<u32> for RtpType {
	fn from(value: u32) -> Self {
		/* values from discord voice node */
		if value >= 194 && value < 224 {
			Self::Rtcp(value)
		} else {
			Self::Rtp(value)
		}
	}
}

pub struct RtpPayload<'a> {
	pub ty: u8,
	pub sequence: u16,
	pub timestamp: u32,
	pub ssrc: u32,
	pub data: &'a [u8]
}

pub struct OpusFrame;

impl OpusFrame {
	pub const SILENCE: &'static [u8] = &[0xf8, 0xff, 0xfe];
	pub const SILENCE_DURATION: u64 = 960;

	pub fn new<'a>(sequence: u16, timestamp: u32, ssrc: u32, data: &'a [u8]) -> RtpPayload<'a> {
		RtpPayload {
			ty: PayloadType::Opus as u8,
			sequence,
			timestamp,
			ssrc,
			data
		}
	}
}

impl fmt::Debug for RtpPayload<'_> {
	fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
		const OPUS: u8 = PayloadType::Opus as u8;

		match self.ty {
			OPUS => {
				let mut opus = fmt.debug_struct("Opus");

				opus.field("sequence", &self.sequence);
				opus.field("timestamp", &self.timestamp);
				opus.field("ssrc", &self.ssrc);

				if self.data == OpusFrame::SILENCE {
					opus.field("data", &format_args!("<silence>"));
				} else {
					opus.field("data", &format_args!("{} bytes", self.data.len()));
				}

				opus.finish()
			}

			_ => fmt
				.debug_struct("Rtp")
				.field("type", &self.ty)
				.field("sequence", &self.sequence)
				.field("timestamp", &self.timestamp)
				.field("ssrc", &self.ssrc)
				.field("data", &format_args!("{} bytes", self.data.len()))
				.finish()
		}
	}
}

pub struct Opus {
	pub sequence: u16,
	pub timestamp: u32,
	pub ssrc: u32,
	pub audio_level: Option<i32>,
	pub speaking_flags: Option<BitFlags<SpeakingFlag>>,
	pub data: Vec<u8>
}

impl Opus {
	pub fn parse(buf: &[u8]) -> Option<Opus> {
		let packet = RtpPacket::new(buf)?;

		let mut payload = packet.payload();
		let mut opus = Opus {
			sequence: packet.get_sequence(),
			timestamp: packet.get_timestamp(),
			ssrc: packet.get_ssrc(),
			audio_level: None,
			speaking_flags: None,
			data: Vec::new()
		};

		if let Some(extension) = packet.get_extension_header().first() {
			let extension_length = extension.length as usize * 4;

			if payload.len() < extension_length {
				return None;
			}

			let extensions =
				ExtensionIterator::new(extension.profile, &payload[0..extension_length]);

			for (id, data) in extensions {
				match ExtensionId::from_u8(id) {
					Some(ExtensionId::AudioLevel) => {
						let loudness = data[0] as i32 & 0x7f;

						opus.audio_level = Some(-loudness);
					}

					Some(ExtensionId::SpeakingFlags) => {
						opus.speaking_flags =
							Some(unsafe { BitFlags::from_bits_unchecked(data[0] as u32) });
					}

					_ => ()
				}
			}

			payload = &payload[extension_length..];
		}

		opus.data = payload.into();

		Some(opus)
	}
}

impl fmt::Debug for Opus {
	fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut opus = fmt.debug_struct("Opus");

		opus.field("sequence", &self.sequence);
		opus.field("timestamp", &self.timestamp);
		opus.field("ssrc", &self.ssrc);

		if self.data == OpusFrame::SILENCE {
			opus.field("data", &format_args!("<silence>"));
		} else {
			opus.field("data", &format_args!("{} bytes", self.data.len()));
		}

		if let Some(audio_level) = &self.audio_level {
			opus.field("audio_level", &format_args!("{} dBov", audio_level));
		}

		if let Some(speaking_flags) = &self.speaking_flags {
			opus.field("speaking_flags", &format_args!("{}", speaking_flags));
		}

		opus.finish()
	}
}

#[allow(dead_code)]
pub struct RtcConn {
	socket: DatagramSocket,
	remote_addr: SocketAddr,
	local_addr: SocketAddr,
	mode: EncryptionMode,
	crypto: Crypto
}

#[async_fn]
impl RtcConn {
	async fn read_socket(&self, buf: &mut [u8], received: &mut bool) -> Result<&mut [u8]> {
		let mut vec = IoVec {
			base: MutPtr::from(buf.as_mut_ptr()).as_unit(),
			len: buf.len()
		};

		loop {
			let mut addr = AddressStorage::new();
			let mut header = MessageHeader {
				address: MutPtr::from(&mut addr).as_unit(),
				address_len: size_of::<AddressStorage>() as u32,

				iov: MutPtr::from(&mut vec),
				iov_len: 1,

				..Default::default()
			};

			let len = self.socket.recvmsg(&mut header, 0).await?;

			if self.remote_addr != addr.try_into().unwrap() {
				continue;
			}

			*received = true;

			if header.flags().intersects(MessageFlag::Truncate) {
				/* could not fit the full packet into our buffer. data is lost */
				continue;
			}

			break Ok(&mut buf[0..len]);
		}
	}

	async fn recv_valid_ip_discovery(
		&self, buf: &mut [u8], received: &mut bool, expect_ssrc: u32
	) -> Result<SocketAddr> {
		Ok(loop {
			let buf = self.read_socket(buf, received).await?;
			match IpDiscovery::parse(buf) {
				Some((ssrc, addr)) if ssrc == expect_ssrc => break addr,
				_ => continue
			}
		})
	}

	pub async fn connect(ip: &str, port: u16, ssrc: u32) -> Result<Self> {
		let remote_ip = ip.parse::<IpAddr>().map_err(Error::map_as_invalid_data)?;
		let remote_addr = SocketAddr::new(remote_ip, port);

		let socket = Udp::connect(remote_addr).await?;

		let mut rtc = RtcConn {
			socket,
			remote_addr,
			local_addr: remote_addr,
			crypto: Crypto::new(),
			mode: EncryptionMode::None
		};

		let mut local_addr = None;
		let mut error = None;

		for _ in 0..6 {
			trace!(target: &rtc, "<< IpDiscovery {{ ssrc: {} }}", ssrc);

			let mut buf = IpDiscovery::new(ssrc);

			rtc.socket.send(&buf, 0).await?;

			let mut received = false;

			match select(
				rtc.recv_valid_ip_discovery(&mut buf, &mut received, ssrc),
				sleep(Duration::from_secs(5))
			)
			.await
			{
				Select::First(addr, _) => {
					let addr = addr?;

					trace!(target: &rtc, ">> IpDiscovery {{ addr: {} }}", addr);

					local_addr = Some(addr);

					break;
				}

				Select::Second(..) => {
					error = Some(if received {
						Error::new(ErrorKind::InvalidData, "Invalid IP discovery response")
					} else {
						Error::new(ErrorKind::TimedOut, "RTC connect timed out")
					});

					continue;
				}
			}
		}

		rtc.local_addr = local_addr.ok_or_else(|| error.unwrap())?;

		Ok(rtc)
	}

	#[allow(dead_code)]
	pub fn remote_addr(&self) -> SocketAddr {
		self.remote_addr
	}

	pub fn local_addr(&self) -> SocketAddr {
		self.local_addr
	}

	pub fn initialize_crypto(&mut self, mode: EncryptionMode, key: &Key) {
		self.crypto.set_mode(mode, key);
		self.mode = mode;
	}

	pub fn encryption_mode(&self) -> EncryptionMode {
		self.mode
	}

	pub async fn send_heartbeat(&self, nonce: u32) -> Result<()> {
		let mut payload = [0u8; KeepAlivePacket::minimum_packet_size()];
		let mut packet = MutableKeepAlivePacket::new(&mut payload).unwrap();

		packet.set_prefix(KeepAlive::PREFIX);
		packet.set_nonce(nonce);

		self.socket.send(&payload, 0).await?;

		Ok(())
	}

	pub fn max_packet_size(&self) -> usize {
		let mut max_size = MAX_PACKET_SIZE;

		if self.remote_addr.is_ipv4() {
			max_size -= IPV4_UDP_HEADERS_SIZE;
		} else {
			/* discord never uses ipv6, just future proofing */
			max_size -= IPV6_UDP_HEADERS_SIZE;
		}

		max_size
	}

	pub fn nonce_size(&self) -> usize {
		self.mode.nonce_size()
	}

	pub fn max_rtp_payload(&self) -> usize {
		let mut max_size = self.max_packet_size();

		max_size -= RtpPacket::minimum_packet_size();
		max_size -= Crypto::TAG_SIZE;
		max_size -= self.nonce_size();
		max_size
	}

	pub async fn send_rtp<'a>(&self, rtp: impl Into<RtpPayload<'a>>, nonce: &[u8]) -> Result<()> {
		let rtp = rtp.into();

		if rtp.data.len() > self.max_rtp_payload() {
			return Err(Error::new(ErrorKind::InvalidInput, "Packet too large"));
		}

		let mut payload = [MaybeUninit::<u8>::uninit(); MAX_PACKET_SIZE];
		let payload: &mut [u8] = unsafe { transmute(&mut payload[..]) };

		let len = {
			let (header, bytes) = (&mut payload[..]).split_at_mut(RtpPacket::minimum_packet_size());
			let (data, bytes) = bytes.split_at_mut(rtp.data.len());
			let (_tag, bytes) = bytes.split_at_mut(Crypto::TAG_SIZE);
			let (nonce_buf, _) = bytes.split_at_mut(self.nonce_size());

			let mut packet = MutableRtpPacket::new(header).unwrap();

			packet.set_version(2);
			packet.set_padding(0);
			packet.set_extension(0);
			packet.set_csrc_count(0);
			packet.set_marker(0);
			packet.set_packet_type(rtp.ty);
			packet.set_sequence(rtp.sequence);
			packet.set_timestamp(rtp.timestamp);
			packet.set_ssrc(rtp.ssrc);

			data.copy_from_slice(rtp.data);

			if nonce_buf.len() != nonce.len() {
				return Err(Error::new(ErrorKind::InvalidInput, "Nonce size mismatch"));
			}

			nonce_buf.copy_from_slice(nonce);

			self.crypto.encrypt_in_place(
				payload,
				RtpPacket::minimum_packet_size(),
				rtp.data.len(),
				nonce.len()
			)?
		};

		self.socket.send(&payload[0..len], 0).await?;

		Ok(())
	}

	fn decrypt_packet<'a>(&self, packet_type: &RtpType, buf: &'a mut [u8]) -> Option<&'a mut [u8]> {
		let aead_len = match packet_type {
			RtpType::Rtp(_) => self.mode.rtp_aead_len(&RtpPacket::new(buf)?),
			RtpType::Rtcp(_) => self.mode.rtcp_aead_len()
		};

		let plaintext_len = self
			.crypto
			.decrypt_in_place(buf, buf.len(), aead_len, self.nonce_size())
			.ok()?;

		Some(&mut buf[0..plaintext_len + aead_len])
	}

	fn decode_packet<'a>(&self, mut buf: &'a mut [u8]) -> Option<(RtpType, &'a mut [u8])> {
		let rtcp = RtcpPacket::new(buf).unwrap();
		let packet_type = RtpType::from(rtcp.get_packet_type() as u32);
		let has_padding = rtcp.get_padding() != 0;

		buf = self.decrypt_packet(&packet_type, buf)?;

		if has_padding {
			let padding = *buf.last()? as usize;
			let actual_len = buf.len().checked_sub(padding)?;

			buf = &mut buf[0..actual_len];
		}

		Some((packet_type, buf))
	}

	pub async fn read_packet(&self) -> Result<Packet> {
		let mut received = false;

		Ok(loop {
			let mut buf = [0u8; MAX_PACKET_SIZE];
			let buf = self.read_socket(&mut buf, &mut received).await?;

			if buf.len() == KeepAlivePacket::minimum_packet_size() {
				let keepalive = KeepAlivePacket::new(buf).unwrap();

				break Packet::KeepAlive(keepalive.get_nonce());
			}

			if buf.len() < RtcpPacket::minimum_packet_size() {
				continue;
			}

			let (packet_type, buf) = match self.decode_packet(buf) {
				Some(buf) => buf,
				None => continue
			};

			if let RtpType::Rtcp(_) = packet_type {
				let packet = RtcpPacket::new(buf).unwrap();
				let total_len = (packet.get_length() as usize + 1) * 4;

				if buf.len() < total_len {
					continue;
				}
			}

			const OPUS: u32 = PayloadType::Opus as u32;
			const SENDER_REPORT: u32 = PayloadType::SenderReport as u32;
			const RECEIVER_REPORT: u32 = PayloadType::ReceiverReport as u32;

			match packet_type {
				RtpType::Rtp(OPUS) => {
					let opus = match Opus::parse(buf) {
						Some(opus) => opus,
						None => continue
					};

					break Packet::Opus(opus);
				}

				RtpType::Rtcp(SENDER_REPORT) => {
					let report = match SenderReport::parse(buf) {
						Some(packet) => packet,
						None => continue
					};

					break Packet::SenderReport(report);
				}

				RtpType::Rtcp(RECEIVER_REPORT) => {
					let report = match ReceiverReport::parse(buf) {
						Some(packet) => packet,
						None => continue
					};

					break Packet::ReceiverReport(report);
				}

				_ => ()
			}
		})
	}
}
