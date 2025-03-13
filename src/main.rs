use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clap::{Parser, ValueEnum};
use jemallocator::Jemalloc;
use log::{set_max_level, LevelFilter};
use xx_core::{error::*, info};
use xx_pulse::*;

mod node;
pub use node::*;
mod client;
pub use client::*;
mod player;
pub use player::*;
mod voice;

pub mod proto {
	include!(concat!(env!("OUT_DIR"), "/_.rs"));

	pub mod commands {
		include!(concat!(env!("OUT_DIR"), "/commands.rs"));
	}
}

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LogLevel {
	Off,
	Error,
	Warn,
	Info,
	Debug,
	Trace
}

#[derive(Parser)]
#[clap(name = "ying")]
struct Options {
	#[arg(short, long)]
	log_level: Option<LogLevel>,

	#[arg(short, long)]
	ip: Option<IpAddr>,

	#[arg(short, long)]
	port: Option<u16>,

	#[arg(short, long)]
	addr: Option<SocketAddr>
}

#[main]
async fn main() -> Result<()> {
	let args = Options::parse();

	set_max_level(match args.log_level {
		Some(LogLevel::Off) => LevelFilter::Off,
		Some(LogLevel::Error) => LevelFilter::Error,
		Some(LogLevel::Warn) => LevelFilter::Warn,
		Some(LogLevel::Info) => LevelFilter::Info,
		Some(LogLevel::Debug) => LevelFilter::Debug,
		Some(LogLevel::Trace) => LevelFilter::Trace,

		_ => LevelFilter::Info
	});

	let addr = {
		let default_port = 5360;
		let default_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

		SocketAddr::new(
			args.ip.unwrap_or(default_ip),
			args.port.unwrap_or(default_port)
		)
	};

	let node = Node::bind(args.addr.unwrap_or(addr)).await?;
	let addr = node.local_addr().await?;

	info!(target: &node, "== Listening on {}", addr);

	node.run().await
}
