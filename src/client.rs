use std::{
	collections::{hash_map::Entry, HashMap},
	time::Duration
};

use enumflags2::BitFlags;
use prost::{bytes::Bytes, Message as ProtoMessage};
use xx_core::{async_std::*, error, error::*, task::*, trace};
use xx_pulse::*;
use xx_url::ws::*;

use super::*;
use crate::{
	proto::{
		command, message, session_message, voice_connection_control, Command, Message,
		SessionMessage, TrackControl, VoiceConnectionControl
	},
	voice::VoiceConn
};

struct Session {
	id: u64,
	voice: Boxed<VoiceConn>,
	player: Boxed<Player>
}

#[async_fn]
impl Session {
	fn new(id: u64) -> Self {
		let mut voice = VoiceConn::new();
		let mut player = Player::new();

		player.set_voice(voice.get_handle());

		Self { id, voice, player }
	}

	async fn update_voice(&mut self, voice: &VoiceConnectionControl) -> Result<()> {
		use voice_connection_control::Data::*;

		let data = match &voice.data {
			Some(data) => data,
			None => return Ok(())
		};

		match data {
			StateUpdate(state) => {
				trace!(target: self, ">> {:?}", state);

				self.voice.update_voice_state(state).await;
			}

			ServerUpdate(state) => {
				trace!(target: self, ">> {:?}", state);

				self.voice.update_server_state(state).await;
			}

			_ => {
				return Err(Error::new(
					ErrorKind::InvalidData,
					"Unexpected voice connection control type"
				))
			}
		}

		Ok(())
	}

	async fn close(&mut self) {
		self.voice.close().await;
	}

	async fn run_command(&mut self, command: &Command) -> Result<()> {
		use command::Command::*;

		let command = match &command.command {
			Some(command) => command,
			None => return Ok(())
		};

		match command {
			Play(play) => {
				self.player.play(&play.track).await?;
			}

			_ => ()
		}

		Ok(())
	}

	async fn track_control(&mut self, track: &TrackControl) -> Result<()> {
		Ok(())
	}
}

pub struct Client {
	socket: WebSocket,
	missed_pings: u32,
	sessions: HashMap<u64, Session>
}

#[async_fn]
impl Client {
	const MAX_MISSED_PINGS: u32 = 6;
	const PING_INTERVAL: Duration = Duration::from_secs(10);

	pub fn new(socket: WebSocket) -> Boxed<Self> {
		Boxed::new(Self { socket, missed_pings: 0, sessions: HashMap::new() })
	}

	async fn session_message(&mut self, message: &SessionMessage) -> Result<()> {
		use session_message::Data::*;

		let data = match &message.data {
			Some(data) => data,
			None => return Ok(())
		};

		let entry = self.sessions.entry(message.id);

		if let Open(_) = data {
			return match entry {
				Entry::Vacant(entry) => {
					entry.insert(Session::new(message.id));

					trace!(target: self, "++ Session #{}", message.id);

					Ok(())
				}

				Entry::Occupied(_) => Err(Error::new(
					ErrorKind::AlreadyExists,
					"Client tried to open an already existing session"
				))
			};
		}

		let session = match entry {
			Entry::Occupied(session) => session.into_mut(),
			Entry::Vacant(_) => {
				return Err(Error::new(
					ErrorKind::NotFound,
					"Client referenced a non-existent session"
				))
			}
		};

		match data {
			Close(_) => {
				session.close().await;

				self.sessions.remove(&message.id);

				trace!(target: self, "-- Session #{}", message.id);
			}

			Voice(voice) => session.update_voice(voice).await?,
			Track(track) => session.track_control(track).await?,

			Commands(commands) => {
				for command in &commands.command {
					session.run_command(command).await?;
				}
			}

			_ => unreachable!()
		}

		Ok(())
	}

	async fn handle_message(&mut self, message: Message) -> Result<()> {
		use message::Data;

		let data = match &message.data {
			Some(data) => data,
			None => return Ok(())
		};

		match data {
			Data::Ping(ping) => {
				trace!(target: self, ">> {:?}", ping);

				self.missed_pings = 0;

				trace!(target: self, "<< {:?}", ping);
				/* pong! */
				self.socket
					.writer()
					.send_frame(&message.encode_to_vec()[..])
					.await?;
			}

			Data::Session(session_msg) => {
				self.session_message(session_msg).await?;
			}

			Data::Query(_query) => {}

			_ => {
				return Err(Error::new(
					ErrorKind::InvalidData,
					"Unexpected message type"
				))
			}
		}

		Ok(())
	}

	async fn run_loop(&mut self) -> Result<()> {
		while let Some(frame) = self.socket.reader().frames().next().await {
			let frame = frame?;

			match frame {
				Frame::Binary(data) => {
					let message =
						Message::decode(Bytes::from(data)).map_err(Error::map_as_invalid_data)?;

					self.handle_message(message).await?;
				}

				frame @ Frame::Close(..) => {
					trace!(target: self, ">> {}", frame);

					self.socket.writer().send_frame(&frame).await?;
				}

				frame => {
					return Err(Error::new(
						ErrorKind::InvalidData,
						format!("Unexpected frame kind: {:?}", frame)
					))
				}
			}
		}

		Ok(())
	}

	async fn heartbeat_loop(mut this: Handle<Self>) -> Result<()> {
		let mut timer = Timer::new(Self::PING_INTERVAL, BitFlags::default());

		loop {
			this.missed_pings += 1;
			timer.next().await?;

			if this.missed_pings < Self::MAX_MISSED_PINGS {
				continue;
			}

			break Err(Error::new(ErrorKind::TimedOut, "Heartbeat timed out"));
		}
	}

	async fn run_inner(&mut self) -> Result<()> {
		use message::Data;

		loop {
			let handle = self.into();
			let result = select(self.run_loop(), Self::heartbeat_loop(handle))
				.await
				.flatten();

			for session in &mut self.sessions.values_mut() {
				session.close().await;
			}

			let Err(err) = result else {
				break;
			};

			if !self.socket.can_write() {
				break;
			}

			let (error_kind, error_message) = match err.kind() {
				ErrorKind::NotFound | ErrorKind::AlreadyExists => {
					(proto::Error::InvalidSession, err.to_string())
				}

				ErrorKind::TimedOut => (proto::Error::Timeout, "Heartbeat timed out".to_string()),
				ErrorKind::InvalidData => (proto::Error::InvalidMessage, err.to_string()),
				_ => (proto::Error::Other, "".to_string())
			};

			let message = Message { data: Some(Data::Error(error_kind as i32)) };

			let _ = self
				.socket
				.writer()
				.send_frame(Frame::binary(&message.encode_to_vec()[..]))
				.await;
			let _ = self
				.socket
				.writer()
				.send_frame(Frame::close(
					CloseCode::ProtocolError as u16,
					error_message.as_bytes()
				))
				.await;
			return Err(err);
		}

		Ok(())
	}

	pub async fn run(&mut self) {
		info!(target: self, "++ New client");

		match self.run_inner().await {
			Ok(()) => info!(target: self, "-- Closed"),
			Err(err) => error!(target: self, "== Closed with error: {:?}", err)
		}
	}
}

impl Global for Client {}
