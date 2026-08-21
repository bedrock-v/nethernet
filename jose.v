module nethernet

import crypto.ecdsa
import encoding.base64

// JOSE and ASN.1 helpers.
//
// NetherNet binds an identity to a peer connection with a JWS: the token in the
// SDP carries a public key, and a detached signature over the DTLS fingerprints
// proves the sender holds the matching private key. V's ECDSA bindings speak
// DER signatures and OpenSSL's own key encoding, while JOSE wants raw r||s and
// X.509 SubjectPublicKeyInfo, so the conversions live here.

// base64url_encode encodes without padding, as every JOSE field requires.
fn base64url_encode(data []u8) string {
	return base64.url_encode(data).trim_right('=')
}

// base64url_decode restores the padding V's decoder expects.
fn base64url_decode(text string) ![]u8 {
	mut padded := text
	remainder := padded.len % 4
	if remainder == 2 {
		padded += '=='
	} else if remainder == 3 {
		padded += '='
	} else if remainder != 0 {
		return error('nethernet: base64url string of ${text.len} bytes has no valid padding')
	}
	decoded := base64.url_decode(padded)
	if decoded.len == 0 && text != '' {
		return error('nethernet: invalid base64url string')
	}
	return decoded
}

// curve_key_size is the byte length of one signature component for a curve,
// derived from the length of its uncompressed public point.
fn curve_key_size(point_len int) !int {
	return match point_len {
		65 { 32 }
		97 { 48 }
		133 { 66 }
		else { error('nethernet: unsupported public point of ${point_len} bytes') }
	}
}

// der_signature_to_raw converts a DER `SEQUENCE { INTEGER r, INTEGER s }` into
// the fixed-width r||s concatenation JOSE uses.
fn der_signature_to_raw(der []u8, size int) ![]u8 {
	mut reader := Asn1Reader{
		data: der
	}
	mut body := reader.read(0x30)!
	mut sequence := Asn1Reader{
		data: body
	}
	r := sequence.read(0x02)!
	s := sequence.read(0x02)!
	if sequence.offset != sequence.data.len {
		return error('nethernet: ${sequence.data.len - sequence.offset} trailing bytes in DER signature')
	}

	mut raw := []u8{len: size * 2}
	copy_right_aligned(mut raw[..size], strip_leading_zeros(r), size)!
	copy_right_aligned(mut raw[size..], strip_leading_zeros(s), size)!
	return raw
}

// raw_signature_to_der is the inverse of der_signature_to_raw: it rebuilds the
// DER encoding OpenSSL verifies against.
fn raw_signature_to_der(raw []u8) ![]u8 {
	if raw.len == 0 || raw.len % 2 != 0 {
		return error('nethernet: raw signature of ${raw.len} bytes is not two equal components')
	}
	size := raw.len / 2
	mut body := []u8{}
	body << asn1_integer(raw[..size])
	body << asn1_integer(raw[size..])
	return asn1_tagged(0x30, body)
}

// copy_right_aligned writes value into dst so its least significant byte lands
// last, which is how a fixed-width JOSE component is padded.
fn copy_right_aligned(mut dst []u8, value []u8, size int) ! {
	if value.len > size {
		return error('nethernet: signature component of ${value.len} bytes exceeds ${size}')
	}
	for i, b in value {
		dst[size - value.len + i] = b
	}
}

fn strip_leading_zeros(value []u8) []u8 {
	mut start := 0
	for start < value.len - 1 && value[start] == 0 {
		start++
	}
	return value[start..]
}

// asn1_integer encodes an unsigned big-endian number as a DER INTEGER, adding
// the leading zero that keeps it from reading as negative.
fn asn1_integer(value []u8) []u8 {
	mut body := strip_leading_zeros(value).clone()
	if body.len > 0 && body[0] & 0x80 != 0 {
		body.prepend(u8(0))
	}
	return asn1_tagged(0x02, body)
}

// asn1_tagged wraps a body in a tag and a definite-form length.
fn asn1_tagged(tag u8, body []u8) []u8 {
	mut out := [tag]
	if body.len < 0x80 {
		out << u8(body.len)
	} else {
		mut length := []u8{}
		mut remaining := body.len
		for remaining > 0 {
			length.prepend(u8(remaining & 0xff))
			remaining >>= 8
		}
		out << u8(0x80 | length.len)
		out << length
	}
	out << body
	return out
}

// Asn1Reader walks a DER structure one element at a time.
struct Asn1Reader {
	data []u8
mut:
	offset int
}

// read consumes the next element, checks its tag and returns its body.
fn (mut r Asn1Reader) read(tag u8) ![]u8 {
	if r.offset + 2 > r.data.len {
		return error('nethernet: truncated DER element')
	}
	if r.data[r.offset] != tag {
		return error('nethernet: expected DER tag 0x${tag.hex()}, found 0x${r.data[r.offset].hex()}')
	}
	r.offset++

	mut length := int(r.data[r.offset])
	r.offset++
	if length & 0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || r.offset + count > r.data.len {
			return error('nethernet: unsupported DER length of ${count} bytes')
		}
		length = 0
		for _ in 0 .. count {
			length = int((u32(length) << 8) | u32(r.data[r.offset]))
			r.offset++
		}
	}
	if length < 0 || r.offset + length > r.data.len {
		return error('nethernet: DER element of ${length} bytes exceeds the remaining input')
	}
	body := r.data[r.offset..r.offset + length]
	r.offset += length
	return body
}

// Object identifiers for the SubjectPublicKeyInfo of an EC key. They are
// dynamic arrays rather than fixed ones because the curve is chosen between them
// at runtime and they are not all the same length.
const oid_ec_public_key = [u8(0x06), 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]

const oid_prime256v1 = [u8(0x06), 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]

const oid_secp384r1 = [u8(0x06), 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]

const oid_secp521r1 = [u8(0x06), 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]

// encode_public_key renders a public key as X.509 SubjectPublicKeyInfo DER,
// which is what the `cpk` claim carries in base64.
//
// V exposes only the raw point, so the structure around it is built here. The
// curve is taken from the point length; nothing else distinguishes them.
fn encode_public_key(key ecdsa.PublicKey) ![]u8 {
	point := key.uncompressed_bytes()!
	curve := match point.len {
		65 { oid_prime256v1 }
		97 { oid_secp384r1 }
		133 { oid_secp521r1 }
		else { return error('nethernet: unsupported public point of ${point.len} bytes') }
	}

	mut algorithm := []u8{}
	algorithm << oid_ec_public_key
	algorithm << curve

	// The point goes into a BIT STRING, whose first byte counts the unused bits
	// in the last byte - always zero for a whole number of octets.
	mut bits := [u8(0x00)]
	bits << point

	mut body := asn1_tagged(0x30, algorithm)
	body << asn1_tagged(0x03, bits)
	return asn1_tagged(0x30, body)
}

// decode_public_key reads a SubjectPublicKeyInfo produced by any peer.
fn decode_public_key(der []u8) !ecdsa.PublicKey {
	return ecdsa.pubkey_from_bytes(der) or { error('nethernet: parse public key: ${err.msg()}') }
}
