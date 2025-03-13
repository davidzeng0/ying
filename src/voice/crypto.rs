use aead::{AeadInPlace, Nonce, Tag};
use crypto_common::KeyInit;
use xx_core::{async_std::io::read_into_slice, error::*};

mod algos {
	pub use aes_gcm::Aes256Gcm;
	pub use chacha20poly1305::XChaCha20Poly1305;
	pub use crypto_secretbox::XSalsa20Poly1305;
}

use algos::*;

use super::*;

pub type Key = [u8; 32];

pub enum Algorithm {
	/// Unencrypted (not supported by discord)
	None,

	/// XSalsa and whether or not there is a tailing nonce
	XSalsa20Poly1305(XSalsa20Poly1305, bool),

	/// Aes galosis counter mode
	Aes256Gcm(Aes256Gcm),

	/// Chacha slide
	XChaCha20Poly1305(XChaCha20Poly1305)
}

impl Algorithm {
	const AES_NONCE_SIZE: usize = 12;
	const EXTENDED_NONCE_SIZE: usize = 24;

	fn get_buffers<'a>(
		&self, bytes: &'a mut [u8], nonce_buf: &'a mut [u8; Self::EXTENDED_NONCE_SIZE],
		aead_len: usize, data_len: usize, nonce_len: usize, is_decrypt: bool
	) -> (&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a [u8]) {
		use Algorithm::*;

		let (aead, bytes) = bytes.split_at_mut(aead_len);
		let (data_tag, bytes) = bytes.split_at_mut(data_len + Crypto::TAG_SIZE);
		let nonce = &bytes[0..nonce_len];

		match self {
			XSalsa20Poly1305(_, false) => read_into_slice(nonce_buf, aead),
			_ => read_into_slice(nonce_buf, nonce)
		};

		let (aead, (data, tag)) = match self {
			XSalsa20Poly1305(..) => {
				/* yes, this is slow. no, you should not be using XSalsa20Poly1305 */
				let data_tag = if is_decrypt {
					data_tag.rotate_right(data_len);
					data_tag.split_at_mut(data_len)
				} else {
					data_tag.rotate_right(Crypto::TAG_SIZE);

					let (tag, data) = data_tag.split_at_mut(Crypto::TAG_SIZE);

					(data, tag)
				};

				(&mut aead[0..0], data_tag)
			}
			_ => (aead, data_tag.split_at_mut(data_len))
		};

		let size = match self {
			Aes256Gcm(..) => Self::AES_NONCE_SIZE,
			_ => nonce_buf.len()
		};

		(aead, data, tag, &nonce_buf[0..size])
	}

	fn encrypt_in_place(
		&self, bytes: &mut [u8], aead_len: usize, data_len: usize, nonce_len: usize
	) -> Result<usize> {
		use Algorithm::*;

		if let None = self {
			return Ok(aead_len + data_len);
		}

		let mut nonce = [0u8; Self::EXTENDED_NONCE_SIZE];
		let (aead, data, tag_buf, nonce) =
			self.get_buffers(bytes, &mut nonce, aead_len, data_len, nonce_len, false);

		macro_rules! encrypt_in_place {
			($inner: expr, $algo: ident) => {
				$inner.encrypt_in_place_detached(
					Nonce::<algos::$algo>::from_slice(nonce),
					aead,
					data
				)
			};
		}

		let tag = match self {
			XSalsa20Poly1305(inner, _) => encrypt_in_place!(inner, XSalsa20Poly1305),
			Aes256Gcm(inner) => encrypt_in_place!(inner, Aes256Gcm),
			XChaCha20Poly1305(inner) => encrypt_in_place!(inner, XChaCha20Poly1305),
			_ => unreachable!()
		}
		.map_err(Error::map_as_invalid_data)?;

		tag_buf.copy_from_slice(tag.as_slice());

		Ok(aead_len + data_len + Crypto::TAG_SIZE + nonce_len)
	}

	fn decrypt_in_place(
		&self, bytes: &mut [u8], len: usize, aead_len: usize, nonce_len: usize
	) -> Result<usize> {
		use Algorithm::*;

		if let None = self {
			return Ok(len);
		}

		let data_len = len - aead_len - nonce_len - Crypto::TAG_SIZE;

		let mut nonce = [0u8; Self::EXTENDED_NONCE_SIZE];
		let (aead, data, tag, nonce) =
			self.get_buffers(bytes, &mut nonce, aead_len, data_len, nonce_len, true);

		macro_rules! decrypt_in_place {
			($inner: expr, $algo: ident) => {
				$inner.decrypt_in_place_detached(
					Nonce::<algos::$algo>::from_slice(nonce),
					aead,
					data,
					Tag::<algos::$algo>::from_slice(tag)
				)
			};
		}

		match self {
			XSalsa20Poly1305(inner, _) => decrypt_in_place!(inner, XSalsa20Poly1305),
			Aes256Gcm(inner) => decrypt_in_place!(inner, Aes256Gcm),
			XChaCha20Poly1305(inner) => decrypt_in_place!(inner, XChaCha20Poly1305),
			_ => unreachable!()
		}
		.map_err(Error::map_as_invalid_data)?;

		Ok(data.len())
	}
}

pub struct Crypto {
	algo: Algorithm
}

impl Crypto {
	pub const TAG_SIZE: usize = 16;

	pub fn new() -> Self {
		Self { algo: Algorithm::None }
	}

	pub fn set_mode(&mut self, mode: EncryptionMode, key: &Key) {
		use crypto_common::Key;
		use EncryptionMode::*;

		macro_rules! new_algo {
			($algo: ident $(, $arg: expr)*) => {
				Algorithm::$algo(
					algos::$algo::new(Key::<algos::$algo>::from_slice(key))
					$(, $arg)*
				)
			};
		}

		self.algo = match mode {
			None => Algorithm::None,
			XSalsa20Poly1305 |
			XSalsa20Poly1305Suffix |
			XSalsa20Poly1305Lite |
			XSalsa20Poly1305LiteRtpSize => new_algo!(XSalsa20Poly1305, mode != XSalsa20Poly1305),
			AeadAes256Gcm | AeadAes256GcmRtpSize => new_algo!(Aes256Gcm),
			AeadXChaCha20Poly1305RtpSize => new_algo!(XChaCha20Poly1305)
		}
	}

	pub fn encrypt_in_place(
		&self, bytes: &mut [u8], aead_len: usize, data_len: usize, nonce_len: usize
	) -> Result<usize> {
		let total_size = aead_len
			.checked_add(data_len)
			.unwrap()
			.checked_add(nonce_len)
			.unwrap();
		if bytes.len() < total_size {
			return Err(Error::new(ErrorKind::InvalidInput, "Buffer too small"));
		}

		self.algo
			.encrypt_in_place(bytes, aead_len, data_len, nonce_len)
	}

	pub fn decrypt_in_place(
		&self, bytes: &mut [u8], len: usize, aead_len: usize, nonce_len: usize
	) -> Result<usize> {
		if len < aead_len.checked_add(nonce_len).unwrap() || bytes.len() < len {
			return Err(Error::new(ErrorKind::InvalidData, "Buffer too small"));
		}

		self.algo.decrypt_in_place(bytes, len, aead_len, nonce_len)
	}
}
