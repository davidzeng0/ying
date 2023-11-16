use std::{collections::VecDeque, time::Duration};

use enumflags2::{make_bitflags, BitFlags};
use opus::Repacketizer;
use xx_core::{
	error,
	error::*,
	task::{Boxed, Global, Handle}
};
use xx_mpeg::{Format, HttpResource, Packet, Resource};
use xx_pulse::*;

use crate::{
	proto::Track,
	voice::{OpusFrame, VoiceConn, MAX_PACKET_SIZE}
};

pub struct Player {
	voice: Handle<VoiceConn>,

	samples_remaining: u64,
	silence_samples_remaining: u64,
	dropped_samples: u64,
	sent_samples: u64,

	sequence: u16,
	timestamp: u32,

	packets: VecDeque<Packet>,
	repacketizer: Repacketizer
}

#[async_fn]
impl Player {
	pub const BUFFERED_DURATION: Duration = Duration::from_secs(10);
	pub const BUFFERED_MEM: usize = 1024 * 1024;
	pub const BUFFERED_PACKETS: usize = 4096;
	pub const TICK_DURATION: u64 = 120;

	pub fn new() -> Boxed<Self> {
		Boxed::new(Self {
			voice: unsafe { Handle::null() },

			samples_remaining: 0,
			silence_samples_remaining: 0,
			dropped_samples: 0,
			sent_samples: 0,

			sequence: 0,
			timestamp: 0,

			packets: VecDeque::new(),
			repacketizer: Repacketizer::new().unwrap()
		})
	}

	pub fn set_voice(&mut self, voice: Handle<VoiceConn>) {
		self.voice = voice;
	}

	async fn play_inner(mut this: Handle<Self>, url: String) -> Result<()> {
		let mut timer = Timer::new(Duration::from_millis(20), BitFlags::default());
		let mut resource = Box::new(HttpResource::new(&url));

		resource.set_strategy(xx_url::net::connection::IpStrategy::PreferIpv6);

		let mut format = Format::open(&(resource as Resource)).await?;

		loop {
			let packet = match format.read_packet().await? {
				Some(packet) => packet,
				None => break
			};

			this.packets.push_back(packet);

			if this.packets.len() > 20 {
				timer.next().await?;
			}
		}

		Ok(())
	}

	async fn tick_inner(mut this: Handle<Self>) -> Result<()> {
		let mut timer = Timer::new(
			Duration::from_nanos(2_500_000),
			make_bitflags!(TimerFlag::{Align})
		);

		loop {
			this.tick().await?;
			timer.next().await?;
		}
	}

	pub async fn play(&mut self, track: &Track) -> Result<()> {
		let url = track.url.as_ref().unwrap().clone();

		spawn(Self::play_inner(self.into(), url)).await;
		spawn(Self::tick_inner(self.into())).await;

		Ok(())
	}

	fn step_nonce(&mut self) {}

	async fn send_opus(&mut self, data: &[u8], duration: u64) -> Result<()> {
		let opus = OpusFrame::new(
			self.sequence,
			self.timestamp,
			self.voice.ssrcs().voice().unwrap(),
			data
		);

		self.samples_remaining = duration;
		self.voice.send_rtp(opus, &[0, 0, 0, 0]).await?;
		self.sequence = self.sequence.wrapping_add(1);
		self.timestamp = self.timestamp.wrapping_add(duration as u32);
		self.step_nonce();

		Ok(())
	}

	pub async fn tick(&mut self) -> Result<()> {
		/* leave a little headroom for the repacketizer */
		const PACKET_OVERHEAD_BYTES: usize = 4;

		loop {
			if self.samples_remaining > 0 {
				self.samples_remaining = self.samples_remaining.saturating_sub(Self::TICK_DURATION);

				break;
			}

			if self.voice.is_null() || !self.voice.is_ready() {
				self.dropped_samples += Self::TICK_DURATION;

				break;
			}

			if self.silence_samples_remaining > 0 {
				self.silence_samples_remaining = self
					.silence_samples_remaining
					.saturating_sub(OpusFrame::SILENCE_DURATION);
				self.send_opus(OpusFrame::SILENCE, OpusFrame::SILENCE_DURATION)
					.await?;
				continue;
			}

			let first_packet = match self.packets.pop_front() {
				Some(packet) => packet,
				None => {
					self.dropped_samples += OpusFrame::SILENCE_DURATION;
					self.silence_samples_remaining = OpusFrame::SILENCE_DURATION;

					continue;
				}
			};

			let mut buffer = [0u8; MAX_PACKET_SIZE];
			let mut overhead = PACKET_OVERHEAD_BYTES;
			let buffer = &mut buffer[0..self.voice.max_rtp_payload().unwrap()];

			if first_packet.data().len() > buffer.len() - overhead {
				self.dropped_samples += first_packet.duration;
				self.silence_samples_remaining = first_packet.duration;

				continue;
			}

			let mut state = self.repacketizer.begin();
			let mut duration = first_packet.duration;
			let mut len = first_packet.data().len();
			let mut added = 0;

			state
				.cat(first_packet.data())
				.map_err(Error::map_as_invalid_data)?;

			while let Some(packet) = self.packets.get(added) {
				let remaining = match (buffer.len() - len).checked_sub(overhead) {
					Some(remaining) => remaining,
					None => break
				};

				if packet.data().len() > remaining {
					break;
				}

				match state.cat(packet.data()) {
					Ok(()) => {
						duration += packet.duration;
						len += packet.data().len();
						overhead += PACKET_OVERHEAD_BYTES;
					}

					Err(_) => break
				}

				added += 1;
			}

			match state.out(buffer) {
				Ok(len) => {
					self.sent_samples = duration;
					self.send_opus(&buffer[0..len], duration).await?;
				}

				Err(err) => {
					error!(target: self, "== Failed to repacketize: {:?}", err);

					return Err(Error::map_as_other(err));
				}
			}

			self.packets.drain(0..added);

			continue;
		}

		Ok(())
	}
}

impl Global for Player {}
