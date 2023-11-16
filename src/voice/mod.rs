mod ws;
use ws::*;
mod discord;
use discord::*;
mod rtp;
use rtp::*;
mod crypto;
use crypto::*;
mod rtc;
pub use rtc::*;
mod connection;
pub use connection::*;
pub use discord::MAX_PACKET_SIZE;

pub const IPV4_UDP_HEADERS_SIZE: usize = 28;
pub const IPV6_UDP_HEADERS_SIZE: usize = 48;
