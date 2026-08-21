// Package discovery implements the LAN half of NetherNet.
//
// A Bedrock client looking for games broadcasts on UDP port 7551; a server
// answers with a description of its world, and from then on the same socket
// carries the NetherNet signals that negotiate the peer connection. Every
// packet is encrypted and authenticated under a key derived from a constant, so
// the encryption obfuscates rather than protects - the real authentication is
// DTLS, one layer up.
module discovery

import crypto.aes
import crypto.hmac
import crypto.sha256

// application_id is the constant the discovery key is derived from. Minecraft
// uses it to keep unrelated traffic on the port from being decoded, which is
// all the key is good for: everybody has it.
const application_id = u64(0xdeadbeef)

const key = sha256.sum(le_u64(application_id))

const block_size = 16

// checksum_size is the length of the HMAC that prefixes every packet.
const checksum_size = 32

// encrypt applies AES-ECB with PKCS#7 padding.
//
// ECB leaks which blocks of a message repeat, and that is a real weakness in
// any other setting. Here it is what the game does, and interoperating means
// doing the same.
fn encrypt(src []u8) []u8 {
	block := aes.new_cipher(key[..])
	padded := pad(src)

	mut dst := []u8{len: padded.len}
	for offset := 0; offset < padded.len; offset += block_size {
		// The slice has to alias dst, not copy it: block.encrypt writes through it.
		mut chunk := unsafe { dst[offset..offset + block_size] }
		block.encrypt(mut chunk, padded[offset..offset + block_size])
	}
	return dst
}

// decrypt reverses encrypt, rejecting anything that is not a whole number of
// blocks or is not correctly padded.
fn decrypt(src []u8) ![]u8 {
	if src.len == 0 || src.len % block_size != 0 {
		return error('discovery: ciphertext of ${src.len} bytes is not a whole number of blocks')
	}
	block := aes.new_cipher(key[..])

	mut dst := []u8{len: src.len}
	for offset := 0; offset < src.len; offset += block_size {
		mut chunk := unsafe { dst[offset..offset + block_size] }
		block.decrypt(mut chunk, src[offset..offset + block_size])
	}
	return unpad(dst)
}

// checksum is the HMAC that authenticates a packet's plaintext.
fn checksum(payload []u8) []u8 {
	return hmac.new(key[..], payload, sha256.sum, sha256.block_size)
}

// pad appends PKCS#7 padding, always adding at least one byte so the padding is
// never ambiguous.
fn pad(src []u8) []u8 {
	count := block_size - (src.len % block_size)
	mut out := src.clone()
	for _ in 0 .. count {
		out << u8(count)
	}
	return out
}

fn unpad(src []u8) ![]u8 {
	if src.len == 0 {
		return error('discovery: nothing to unpad')
	}
	count := int(src[src.len - 1])
	if count == 0 || count > block_size || count > src.len {
		return error('discovery: invalid padding length ${count}')
	}
	for i := src.len - count; i < src.len; i++ {
		if int(src[i]) != count {
			return error('discovery: inconsistent padding')
		}
	}
	return src[..src.len - count]
}

// le_u64 encodes a number the way every length and identifier on this wire is
// encoded: little-endian.
fn le_u64(value u64) []u8 {
	mut out := []u8{len: 8}
	mut remaining := value
	for i in 0 .. 8 {
		out[i] = u8(remaining & 0xff)
		remaining >>= 8
	}
	return out
}
