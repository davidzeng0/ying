use jemallocator::Jemalloc;
use log::set_max_level;
use xx_core::{error::Result, info};
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

#[async_fn]
async fn start_node() -> Result<()> {
	let node = Node::bind("127.0.0.1:5360").await?;
	let addr = node.local_addr().await?;

	info!(target: &node, "== Listening on {}", addr);

	node.run().await
}

fn main() {
	let mut runtime = Runtime::new().unwrap();

	runtime.block_on(start_node()).unwrap();
}
