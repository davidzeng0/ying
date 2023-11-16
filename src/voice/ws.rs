use std::fmt;

use enumflags2::bitflags;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, from_value, to_string, to_value, Value};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Identify {
	pub server_id: String,
	pub user_id: String,
	pub session_id: String,
	pub token: String
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProtocolData {
	pub address: String,
	pub mode: String,
	pub port: u16
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectProtocol {
	pub protocol: String,
	pub data: ProtocolData
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ready {
	pub ip: String,
	pub ssrc: u32,
	pub port: u16,
	pub modes: Vec<String>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Heartbeat {
	/* the spec allows for any value that gets sent back, but we only use u32 and we should
	 * expect u32s in response */
	pub nonce: u32
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionDescription {
	pub mode: String,
	pub secret_key: Vec<u8>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Speaking {
	pub speaking: u32,
	pub delay: u32,
	pub ssrc: u32
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserSpeaking {
	pub user_id: String,
	pub ssrc: u32,
	pub speaking: u32
}

#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpeakingFlag {
	Microphone = 1 << 0,
	Soundshare = 1 << 1,
	Priority   = 1 << 2
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeartbeatAck {
	pub nonce: u32
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hello {
	pub heartbeat_interval: f64
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resume {
	pub server_id: String,
	pub session_id: String,
	pub token: String
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resumed {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientDisconnect {/* to be reverse engineered */}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MediaSinkWants {
	pub any: u32
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromPrimitive)]
pub enum Opcode {
	Identify = 0,
	SelectProtocol,
	Ready,
	Heartbeat,
	SessionDescription,
	Speaking,
	HeartbeatAck,
	Resume,
	Hello,
	Resumed,
	Video    = 12,
	ClientDisconnect,
	SessionUpdate,
	MediaSinkWants,
	VoiceBackendVersion,
	ChannelOptionsUpdate,
	Flags,
	SpeedTest,
	Platform
}

pub enum Op {
	Identify(Identify),
	SelectProtocol(SelectProtocol),
	Ready(Ready),
	Heartbeat(Heartbeat),
	SessionDescription(SessionDescription),
	Speaking(Speaking),
	UserSpeaking(UserSpeaking),
	HeartbeatAck(HeartbeatAck),
	Hello(Hello),
	MediaSinkWants(MediaSinkWants),
	Other(u32, Value)
}

impl fmt::Debug for Op {
	fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Op::Identify(inner) => inner.fmt(fmt),
			Op::SelectProtocol(inner) => inner.fmt(fmt),
			Op::Ready(inner) => inner.fmt(fmt),
			Op::Heartbeat(inner) => inner.fmt(fmt),
			Op::SessionDescription(inner) => inner.fmt(fmt),
			Op::Speaking(inner) => inner.fmt(fmt),
			Op::UserSpeaking(inner) => inner.fmt(fmt),
			Op::HeartbeatAck(inner) => inner.fmt(fmt),
			Op::Hello(inner) => inner.fmt(fmt),
			Op::MediaSinkWants(inner) => inner.fmt(fmt),
			Op::Other(op, value) => fmt
				.debug_struct("Other")
				.field("op", op)
				.field("value", value)
				.finish()
		}
	}
}

macro_rules! into_op {
	($type: ident) => {
		impl From<$type> for Op {
			fn from(value: $type) -> Self {
				Self::$type(value)
			}
		}
	};
}

into_op!(Identify);
into_op!(SelectProtocol);
into_op!(Ready);
into_op!(Heartbeat);
into_op!(SessionDescription);
into_op!(Speaking);
into_op!(UserSpeaking);
into_op!(HeartbeatAck);
into_op!(Hello);
into_op!(MediaSinkWants);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Message {
	op: u32,
	d: Value
}

impl Message {
	fn new(op: Opcode, value: &impl Serialize) -> Result<Self, serde_json::Error> {
		Ok(Message { op: op as u32, d: to_value(value)? })
	}
}

impl Op {
	pub fn to_string(&self) -> Result<String, serde_json::Error> {
		let message = match self {
			Self::Identify(identify) => Message::new(Opcode::Identify, identify),
			Self::SelectProtocol(select) => Message::new(Opcode::SelectProtocol, select),
			Self::Ready(ready) => Message::new(Opcode::Ready, ready),
			Self::Heartbeat(heartbeat) => Message::new(Opcode::Heartbeat, heartbeat),
			Self::SessionDescription(session) => Message::new(Opcode::SessionDescription, session),
			Self::Speaking(speaking) => Message::new(Opcode::Speaking, speaking),
			Self::UserSpeaking(speaking) => Message::new(Opcode::Speaking, speaking),
			Self::HeartbeatAck(ack) => Message::new(Opcode::HeartbeatAck, ack),
			Self::Hello(hello) => Message::new(Opcode::Hello, hello),
			Self::MediaSinkWants(sink) => Message::new(Opcode::MediaSinkWants, sink),
			Self::Other(code, value) => Ok(Message { op: *code, d: value.clone() })
		};

		to_string(&message?)
	}

	pub fn from_str(str: &str) -> Result<Self, serde_json::Error> {
		let message: Message = from_str(str)?;

		Ok(match Opcode::from_u32(message.op) {
			Some(Opcode::Identify) => from_value::<Identify>(message.d)?.into(),
			Some(Opcode::SelectProtocol) => from_value::<SelectProtocol>(message.d)?.into(),
			Some(Opcode::Ready) => from_value::<Ready>(message.d)?.into(),
			Some(Opcode::Heartbeat) => from_value::<Heartbeat>(message.d)?.into(),
			Some(Opcode::SessionDescription) => from_value::<SessionDescription>(message.d)?.into(),
			Some(Opcode::Speaking) => from_value::<UserSpeaking>(message.d)?.into(),
			Some(Opcode::HeartbeatAck) => from_value::<HeartbeatAck>(message.d)?.into(),
			Some(Opcode::Hello) => from_value::<Hello>(message.d)?.into(),
			Some(Opcode::MediaSinkWants) => from_value::<MediaSinkWants>(message.d)?.into(),

			_ => Op::Other(message.op, message.d)
		})
	}
}
