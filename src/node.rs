use std::net::{SocketAddr, ToSocketAddrs};

use xx_core::{error, error::*};
use xx_pulse::*;
use xx_url::ws::*;

use super::*;

pub struct Node {
	server: WebSocketServer
}

#[async_fn]
impl Node {
	pub async fn bind<A: ToSocketAddrs>(addrs: A) -> Result<Self> {
		let server = WebSocketServer::bind(addrs, WebSocketOptions::new()).await?;

		Ok(Self { server })
	}

	pub async fn local_addr(&self) -> Result<SocketAddr> {
		self.server.local_addr().await
	}

	async fn client_start(handle: WebSocketHandle) {
		match handle.await {
			Ok(ws) => Client::new(ws).run().await,
			Err(err) => {
				error!("== Failed to accept client: {:?}", err);

				return;
			}
		}
	}

	pub async fn run(&self) -> Result<()> {
		loop {
			let handle = self.server.accept().await?;

			spawn(Self::client_start(handle)).await;
		}
	}
}
