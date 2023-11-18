use jemallocator::Jemalloc;
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

#[main]
async fn main() -> Result<()> {
	let node = Node::bind("127.0.0.1:5360").await?;
	let addr = node.local_addr().await?;

	info!(target: &node, "== Listening on {}", addr);

	node.run().await
}
