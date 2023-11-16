use std::io::Result;

use prost_build::compile_protos;

fn main() -> Result<()> {
	compile_protos(&["message.proto"], &["ying-proto"])?;

	Ok(())
}
