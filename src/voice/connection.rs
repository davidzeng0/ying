use std::{
	collections::VecDeque,
	time::{Duration, Instant}
};

use enumflags2::{make_bitflags, BitFlags};
use rand::random;
use xx_core::{
	async_std::{io::unexpected_end_of_stream, AsyncIteratorExt},
	debug, error,
	error::*,
	task::{Boxed, Global, Handle},
	trace
};
use xx_pulse::*;
use xx_url::ws::{self, *};

use super::*;
use crate::proto::{VoiceServerUpdate, VoiceStateUpdate};

#[allow(dead_code)]
struct VoiceState {
	server_id: String,
	user_id: String,
	session_id: String,
	channel_id: Option<String>,
	mute: bool,
	deaf: bool
}

struct ServerState {
	endpoint: Option<String>,
	token: String
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum State {
	Idle,
	Connecting,
	Identifying,
	Resuming,
	RtcConnecting,
	SelectingProtocol,
	Ready,
	Disconnected,
	Reconnecting
}

struct ConnectData {
	server_id: String,
	user_id: String,
	session_id: String,
	token: String,
	endpoint: String
}

#[derive(Clone, Copy)]
struct RtcHeartbeat {
	nonce: u32,
	sent: Instant
}

#[derive(Default)]
pub struct SynchronizationSources {
	voice: Option<u32>
}

impl SynchronizationSources {
	pub fn voice(&self) -> Option<u32> {
		self.voice.clone()
	}
}

pub struct VoiceConn {
	state: State,
	voice_state: Option<VoiceState>,
	server_state: Option<ServerState>,

	ssrcs: SynchronizationSources,

	ws: Option<WebSocket>,
	ws_send_queue: VecDeque<Op>,

	ws_heartbeat_counter: u32,
	ws_heartbeat_ack: u32,
	ws_heartbeat_sent: Instant,
	ws_ping: Duration,

	rtc: Option<RtcConn>,

	rtc_heartbeat_counter: u32,
	rtc_heartbeats: VecDeque<RtcHeartbeat>,
	rtc_ping: Duration,

	ws_read_task: Option<JoinHandle<()>>,
	ws_heartbeat_task: Option<JoinHandle<()>>,
	ws_send_task: Option<JoinHandle<()>>,

	rtc_read_task: Option<JoinHandle<()>>,
	rtc_heartbeat_task: Option<JoinHandle<()>>
}

fn pick_fastest_encryption_mode(modes: &Vec<String>) -> Result<EncryptionMode> {
	use EncryptionMode::*;

	let modes_by_priority = [
		AeadAes256GcmRtpSize,
		AeadAes256Gcm,
		AeadXChaCha20Poly1305RtpSize,
		XSalsa20Poly1305Lite,
		XSalsa20Poly1305LiteRtpSize,
		XSalsa20Poly1305Suffix,
		XSalsa20Poly1305
	];

	let mut result = Option::None;

	for mode in modes_by_priority {
		if modes.iter().any(|m| m == mode.to_str()) {
			result = Some(mode);

			break;
		}
	}

	result.ok_or_else(|| Error::new(ErrorKind::Other, "No supported encryption methods"))
}

#[allow(dead_code)]
#[async_fn]
impl VoiceConn {
	pub fn new() -> Boxed<Self> {
		Boxed::new(Self {
			state: State::Idle,
			voice_state: None,
			server_state: None,

			ssrcs: SynchronizationSources::default(),

			ws: None,
			ws_send_queue: VecDeque::new(),

			ws_heartbeat_counter: 0,
			ws_heartbeat_ack: 0,
			ws_heartbeat_sent: Instant::now(),
			ws_ping: Duration::ZERO,

			rtc: None,

			rtc_heartbeat_counter: 0,
			rtc_heartbeats: VecDeque::new(),
			rtc_ping: Duration::ZERO,

			ws_read_task: None,
			ws_send_task: None,
			ws_heartbeat_task: None,

			rtc_read_task: None,
			rtc_heartbeat_task: None
		})
	}

	fn ws(&mut self) -> &mut WebSocket {
		self.ws.as_mut().unwrap()
	}

	fn rtc(&self) -> &RtcConn {
		self.rtc.as_ref().unwrap()
	}

	async fn task_entry<T: Task<Output = Result<()>>>(mut this: Handle<Self>, task: T) {
		let result = task.await;

		if let Err(err) = result {
			if err.is_interrupted() {
				return;
			}

			error!(target: this.as_mut(), "== Error in voice connection: {:?}", err);

			this.close().await;
		}
	}

	async fn spawn<T: Task<Output = Result<()>> + 'static>(&mut self, task: T) -> JoinHandle<()> {
		spawn(Self::task_entry(self.into(), task)).await
	}

	async fn send_messages(mut this: Handle<Self>) -> Result<()> {
		let mut writer = this.as_mut().ws().writer();

		while let Some(op) = this.ws_send_queue.pop_front() {
			let frame = Frame::Text(op.to_string().map_err(Error::map_as_other)?);

			writer.send_frame(&frame).await?;
		}

		this.ws_send_task = None;

		Ok(())
	}

	async fn send_op(&mut self, op: impl Into<Op>) {
		let mut this = Handle::from(self);
		let op = op.into();

		trace!(target: this.as_mut(), "<< {:?}", op);

		this.ws_send_queue.push_back(op);

		if this.ws_send_task.is_none() {
			let task = Self::send_messages(this);

			this.ws_send_task = Some(this.spawn(task).await);
		}
	}

	async fn send_media_sink_wants(&mut self) {
		let any = if self.is_deaf() { 0 } else { 100 };

		self.send_op(MediaSinkWants { any }).await;
	}

	async fn heartbeat(mut this: Handle<Self>, interval: Duration) -> Result<()> {
		let mut timer = Timer::new(interval, BitFlags::default());

		loop {
			timer.next().await?;

			let mut cur = this.ws_heartbeat_counter;

			if cur != this.ws_heartbeat_ack {
				break;
			}

			cur = cur.wrapping_add(1);
			this.ws_heartbeat_counter = cur;
			this.ws_heartbeat_sent = Instant::now();
			this.send_op(Heartbeat { nonce: cur }).await;
		}

		Err(Error::new(
			ErrorKind::TimedOut,
			"WebSocket heartbeat timed out"
		))
	}

	async fn handle_rtc_packet(&mut self, packet: Packet) -> Result<()> {
		let rtc = self.rtc.as_ref().unwrap();

		match packet {
			Packet::KeepAlive(nonce) => {
				let mut ping = None;

				if let Some((pos, hb)) = self
					.rtc_heartbeats
					.iter()
					.enumerate()
					.find(|(_, hb)| hb.nonce == nonce)
				{
					self.rtc_ping = ping.insert(hb.sent.elapsed()).clone();
					self.rtc_heartbeats.drain(0..pos);
				}

				if let Some(ping) = ping {
					trace!(target: rtc, ">> KeepAlive {{ nonce: {} }}, Ping = {:?}", nonce, ping);
				} else {
					trace!(target: rtc, ">> KeepAlive {{ nonce: {} }}, Ping = ???", nonce);
				}
			}

			Packet::Opus(opus) => {
				trace!(
					target: rtc,
					">> {:?}",
					opus
				);
			}

			Packet::ReceiverReport(receiver_report) => {
				for report in receiver_report.reports {
					trace!(target: rtc, ">> ReceiverReport {{ sent: {}, lost: {}, jitter: {} }}", report.highest_sequence, report.cumulative_lost, report.interarrival_jitter);
				}
			}

			Packet::SenderReport(sender_report) => {
				trace!(target: rtc, ">> {:?}", sender_report);
			}
		}

		Ok(())
	}

	async fn rtc_read(mut this: Handle<Self>) -> Result<()> {
		let rtc = this.as_mut().rtc();

		loop {
			let packet = rtc.read_packet().await?;

			this.handle_rtc_packet(packet).await?;
		}
	}

	async fn rtc_heartbeat(mut this: Handle<Self>) -> Result<()> {
		let mut timer = Timer::new(Duration::from_secs(5), BitFlags::default());
		let rtc = this.as_mut().rtc();

		/* very rare case, but try to reduce interference with past rtcs */
		this.rtc_heartbeat_counter = random();

		loop {
			timer.next().await?;

			let heartbeats = &mut this.as_mut().rtc_heartbeats;

			if heartbeats.len() >= KeepAlive::MAX {
				break;
			}

			let nonce = this.rtc_heartbeat_counter;

			this.rtc_heartbeat_counter = nonce.wrapping_add(1);

			trace!(target: rtc, "<< KeepAlive {{ nonce: {} }}", nonce);

			heartbeats.push_back(RtcHeartbeat { nonce, sent: Instant::now() });
			rtc.send_heartbeat(nonce).await?;
		}

		Err(Error::new(ErrorKind::TimedOut, "RTC heartbeat timed out"))
	}

	async fn read_op(&mut self) -> Result<Option<Op>> {
		let frame = match self.ws().reader().frames().next().await {
			Some(frame) => frame,
			None => return Err(unexpected_end_of_stream())
		};

		let frame = frame?;

		match frame {
			Frame::Text(data) => Ok(Some(
				Op::from_str(&data).map_err(Error::map_as_invalid_data)?
			)),

			frame @ Frame::Close(..) => {
				trace!(target: self, ">> {}", frame);

				self.ws().writer().send_frame(&frame).await?;

				Ok(None)
			}

			frame => Err(Error::new(
				ErrorKind::InvalidData,
				format!("Unexpected frame kind: {:?}", frame)
			))
		}
	}

	async fn ws_read(mut this: Handle<Self>, connect: ConnectData) -> Result<()> {
		let this = this.as_mut();
		let start = Instant::now();

		this.state = State::Connecting;

		debug!(target: this, "== Connecting to Discord voice server '{}'", connect.endpoint);

		this.ws = Some(ws::open(&format!("wss://{}/?v=7", connect.endpoint))?.await?);

		debug!(target: this, "== Connected to voice server ({:?})", start.elapsed());

		this.send_op(Identify {
			server_id: connect.server_id.clone(),
			user_id: connect.user_id.clone(),
			session_id: connect.session_id.clone(),
			token: connect.token.clone()
		})
		.await;

		this.send_media_sink_wants().await;
		this.state = State::Identifying;

		loop {
			let op = match this.read_op().await? {
				Some(op) => op,
				None => return Err(Error::new(ErrorKind::Other, "WebSocket closed by peer"))
			};

			match op {
				Op::Hello(hello) => {
					trace!(target: this, ">> {:?}", hello);

					if this.ws_heartbeat_task.is_some() {
						return Err(Error::new(ErrorKind::InvalidData, "Unexpected hello op"));
					}

					fn invalid_heartbeat_interval() -> Error {
						Error::new(ErrorKind::InvalidData, "Invalid heartbeat interval")
					}

					let interval = Duration::try_from_secs_f64(hello.heartbeat_interval / 1000.0)
						.map_err(|_| invalid_heartbeat_interval())?;

					if interval < Duration::from_secs(1) {
						return Err(invalid_heartbeat_interval());
					}

					let task = Self::heartbeat(this.into(), interval);

					this.ws_heartbeat_task = Some(this.spawn(task).await);

					debug!(target: this, "++ Heartbeating every {:?}", interval);
				}

				Op::HeartbeatAck(ack) => {
					let expect = this.ws_heartbeat_ack.wrapping_add(1);

					if expect != this.ws_heartbeat_counter {
						trace!(target: this, ">> {:?}", ack);

						return Err(Error::new(
							ErrorKind::InvalidData,
							"Mismatched heartbeat ack"
						));
					}

					this.ws_heartbeat_ack = expect;
					this.ws_ping = this.ws_heartbeat_sent.elapsed();

					trace!(target: this, ">> {:?}, Ping = {:?}", ack, this.ws_ping);
				}

				Op::Ready(ready) => {
					use super::ws::SpeakingFlag;

					trace!(target: this, ">> {:?}", ready);

					if this.state != State::Identifying {
						return Err(Error::new(ErrorKind::InvalidData, "Unexpected ready op"));
					}

					this.state = State::RtcConnecting;
					this.ssrcs.voice = Some(ready.ssrc);

					let start = Instant::now();

					debug!(target: this, "== RTC Connecting to {}:{}", ready.ip, ready.port);

					let rtc = RtcConn::connect(&ready.ip, ready.port, ready.ssrc).await?;
					let local_addr = rtc.local_addr();

					debug!(target: this, "== RTC Connected ({:?}). Local IP is {}", start.elapsed(), local_addr);

					let mode = pick_fastest_encryption_mode(&ready.modes)?;

					this.send_op(Speaking {
						speaking: make_bitflags!(SpeakingFlag::{Microphone}).bits(),
						delay: 0,
						ssrc: ready.ssrc
					})
					.await;

					this.send_op(SelectProtocol {
						protocol: "udp".to_string(),
						data: ProtocolData {
							address: local_addr.ip().to_string(),
							mode: mode.to_str().to_string(),
							port: local_addr.port()
						}
					})
					.await;

					this.rtc = Some(rtc);
					this.state = State::SelectingProtocol;
				}

				Op::SessionDescription(session) => {
					let secret_key: Key = session.secret_key.try_into().map_err(|_| {
						Error::new(ErrorKind::InvalidData, "Expected a 256 bit encryption key")
					})?;

					let mode = EncryptionMode::from_str(&session.mode).ok_or_else(|| {
						Error::new(
							ErrorKind::InvalidData,
							"Server returned invalid encryption mode"
						)
					})?;

					trace!(target: this, ">> SessionDescription {{ mode: \"{}\", secret_key: {} }}", session.mode, hex::encode(&secret_key));

					if this.state != State::SelectingProtocol {
						return Err(Error::new(
							ErrorKind::InvalidData,
							"Unexpected session description op"
						));
					}

					if this.ws_heartbeat_task.is_none() {
						return Err(Error::new(ErrorKind::Other, "Hello op never received"));
					}

					this.rtc
						.as_mut()
						.unwrap()
						.initialize_crypto(mode, &secret_key);
					let task = Self::rtc_read(this.into());

					this.rtc_read_task = Some(this.spawn(task).await);

					let task = Self::rtc_heartbeat(this.into());

					this.rtc_heartbeat_task = Some(this.spawn(task).await);
					this.state = State::Ready;

					debug!(target: this, "== Voice connection is ready ({:?}). Encryption mode is {:?}", start.elapsed(), mode);
				}

				_ => ()
			}
		}
	}

	async fn connect(&mut self, connect: ConnectData) {
		self.close().await;

		let task = Self::ws_read(self.into(), connect);

		self.ws_read_task = Some(self.spawn(task).await);
	}

	async fn maybe_connect(&mut self) {
		let server_state = self.server_state.as_ref().unwrap();
		let Some(voice_state) = &self.voice_state else {
			return;
		};

		let Some(endpoint) = &server_state.endpoint else {
			return;
		};

		self.connect(ConnectData {
			server_id: voice_state.server_id.clone(),
			user_id: voice_state.user_id.clone(),
			session_id: voice_state.session_id.clone(),
			token: server_state.token.clone(),
			endpoint: endpoint.clone()
		})
		.await;
	}

	pub async fn update_voice_state(&mut self, state: &VoiceStateUpdate) {
		self.voice_state = Some(VoiceState {
			server_id: state.guild_id.clone(),
			user_id: state.user_id.clone(),
			session_id: state.session_id.clone(),
			channel_id: state.channel_id.clone(),
			mute: state.mute(),
			deaf: state.deaf()
		});

		if self.state >= State::Connecting && self.state < State::Disconnected {
			self.send_media_sink_wants().await;
		}
	}

	pub async fn update_server_state(&mut self, server: &VoiceServerUpdate) {
		self.server_state = Some(ServerState {
			endpoint: server.endpoint.clone(),
			token: server.token.clone()
		});

		self.maybe_connect().await;
	}

	pub async fn send_rtp<'a>(&self, rtp: impl Into<RtpPayload<'a>>, nonce: &[u8]) -> Result<()> {
		if self.state != State::Ready {
			return Err(Error::new(
				ErrorKind::Other,
				"Voice connection is not ready"
			));
		}

		let rtp = rtp.into();
		let rtc = self.rtc();

		trace!(target: rtc, "<< {:?}", rtp);

		rtc.send_rtp(rtp, nonce).await
	}

	pub fn ssrcs(&self) -> &SynchronizationSources {
		&self.ssrcs
	}

	pub fn is_ready(&self) -> bool {
		self.state == State::Ready
	}

	pub fn is_mute(&self) -> bool {
		self.voice_state.as_ref().is_some_and(|state| state.mute)
	}

	pub fn is_deaf(&self) -> bool {
		self.voice_state.as_ref().is_some_and(|state| state.deaf)
	}

	pub fn ws_ping(&self) -> Duration {
		self.ws_ping
	}

	pub fn rtc_ping(&self) -> Duration {
		self.rtc_ping
	}

	pub fn max_rtp_payload(&self) -> Option<usize> {
		self.rtc.as_ref().map(|rtc| rtc.max_rtp_payload())
	}

	pub fn encryption_mode(&self) -> Option<EncryptionMode> {
		self.rtc.as_ref().map(|rtc| rtc.encryption_mode())
	}

	pub async fn close(&mut self) {
		let mut this = Handle::from(self);

		if this.state == State::Disconnected || this.state == State::Idle {
			return;
		}

		this.ws_read_task.take().map(|task| task.cancel().await);
		this.ws_heartbeat_task
			.take()
			.map(|task| task.cancel().await);
		this.ws_send_task.take().map(|task| task.cancel().await);
		this.rtc_read_task.take().map(|task| task.cancel().await);
		this.rtc_heartbeat_task
			.take()
			.map(|task| task.cancel().await);

		let this = this.as_mut();

		if let Some(mut ws) = this.ws.take() {
			let close = Frame::Close(CloseCode::Normal as u16, ControlFrame::new());

			trace!(target: this, "<< {}", close);

			let _ = ws.writer().send_frame(&close).await;
		}

		this.ssrcs = SynchronizationSources::default();
		this.ws_send_queue.clear();
		this.ws_heartbeat_counter = 0;
		this.ws_heartbeat_ack = 0;
		this.ws_ping = Duration::ZERO;
		this.rtc = None;
		this.rtc_heartbeats.clear();
		this.rtc_ping = Duration::ZERO;
		this.state = State::Disconnected;
	}
}

impl Drop for VoiceConn {
	fn drop(&mut self) {
		if self.ws.is_some() {
			panic!("Connection not closed properly");
		}
	}
}

impl Global for VoiceConn {}
