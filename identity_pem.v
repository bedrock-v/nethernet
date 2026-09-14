module nethernet

import crypto.ecdsa
import encoding.base64

// PEM encoding for the key a server answers under.
//
// The key outlives the process: a client remembers it, so a server that
// generates a new one on every start looks like a different server every time.
// Storing it as PEM rather than a bare seed means the same file can be read by
// openssl, shared across a fleet and recognised for what it is.

const pem_ec_private_label = 'EC PRIVATE KEY'

const pem_line_width = 64

// encode_private_key_pem renders a key as a SEC 1 `EC PRIVATE KEY` PEM block.
//
// SEC 1 rather than PKCS#8 because that is the form openssl writes by default
// for an EC key, and a file an operator can round trip through their own tools
// is worth more than the newer wrapper.
pub fn encode_private_key_pem(private_key ecdsa.PrivateKey) !string {
	public_key := private_key.public_key()!
	point := public_key.uncompressed_bytes()!
	curve := curve_oid(point.len)!
	seed := private_key.bytes()!

	mut body := asn1_tagged(0x02, [u8(1)])
	// The private value is fixed width for the curve; a seed whose leading bytes
	// are zero comes back short and would name a different key.
	body << asn1_tagged(0x04, left_pad(seed, curve_key_size(point.len)!)!)
	body << asn1_tagged(0xa0, curve)

	mut bits := [u8(0x00)]
	bits << point
	body << asn1_tagged(0xa1, asn1_tagged(0x03, bits))

	return wrap_pem(pem_ec_private_label, asn1_tagged(0x30, body))
}

// parse_private_key_pem reads a key written by encode_private_key_pem, or by
// openssl. A PKCS#8 block is read too, since that is the other form a key on
// disk is likely to be in.
pub fn parse_private_key_pem(text string) !ecdsa.PrivateKey {
	der := unwrap_pem(text)!
	seed, nid := private_key_seed(der)!
	return ecdsa.new_key_from_seed(seed, nid: nid, fixed_size: true)
}

// private_key_seed digs the private value and the curve out of either wrapper.
fn private_key_seed(der []u8) !([]u8, ecdsa.Nid) {
	mut outer := Asn1Reader{
		data: der
	}
	body := outer.read(0x30)!

	mut sequence := Asn1Reader{
		data: body
	}
	version := sequence.read(0x02)!
	if version.len == 1 && version[0] == 1 {
		// SEC 1: version, the private value, then the curve in a context tag.
		seed := sequence.read(0x04)!
		parameters := sequence.read(0xa0) or {
			return error('nethernet: EC private key names no curve')
		}
		return seed, nid_from_oid(parameters)!
	}
	if version.len == 1 && version[0] == 0 {
		// PKCS#8: version, the algorithm identifier, then a SEC 1 key inside an
		// OCTET STRING.
		algorithm := sequence.read(0x30)!
		mut identifier := Asn1Reader{
			data: algorithm
		}
		identifier.read(0x06)!
		curve := identifier.read(0x06)!
		mut oid := [u8(0x06), u8(curve.len)]
		oid << curve
		nid := nid_from_oid(oid)!

		inner := sequence.read(0x04)!
		mut wrapped := Asn1Reader{
			data: inner
		}
		wrapped_body := wrapped.read(0x30)!
		mut fields := Asn1Reader{
			data: wrapped_body
		}
		fields.read(0x02)!
		return fields.read(0x04)!, nid
	}
	return error('nethernet: private key has an unsupported version')
}

fn curve_oid(point_len int) ![]u8 {
	return match point_len {
		65 { oid_prime256v1 }
		97 { oid_secp384r1 }
		133 { oid_secp521r1 }
		else { error('nethernet: unsupported public point of ${point_len} bytes') }
	}
}

fn nid_from_oid(oid []u8) !ecdsa.Nid {
	if oid == oid_prime256v1 {
		return ecdsa.Nid.prime256v1
	}
	if oid == oid_secp384r1 {
		return ecdsa.Nid.secp384r1
	}
	if oid == oid_secp521r1 {
		return ecdsa.Nid.secp521r1
	}
	return error('nethernet: private key names an unsupported curve')
}

// left_pad widens a value to the fixed size the curve requires.
fn left_pad(value []u8, size int) ![]u8 {
	if value.len > size {
		return error('nethernet: private value of ${value.len} bytes exceeds ${size}')
	}
	mut out := []u8{len: size - value.len}
	out << value
	return out
}

fn wrap_pem(label string, der []u8) string {
	encoded := base64.encode(der)
	mut out := '-----BEGIN ${label}-----\n'
	for offset := 0; offset < encoded.len; offset += pem_line_width {
		end := if offset + pem_line_width < encoded.len {
			offset + pem_line_width
		} else {
			encoded.len
		}
		out += encoded[offset..end] + '\n'
	}
	return out + '-----END ${label}-----\n'
}

// unwrap_pem takes the DER out of a PEM block, whatever the block is labelled.
// The label says what the bytes are for, and the parser above works that out
// from the structure anyway.
fn unwrap_pem(text string) ![]u8 {
	mut encoded := ''
	mut inside := false
	for line in text.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed.starts_with('-----BEGIN ') {
			inside = true
			continue
		}
		if trimmed.starts_with('-----END ') {
			inside = false
			continue
		}
		if inside {
			encoded += trimmed
		}
	}
	if encoded == '' {
		return error('nethernet: no PEM block found')
	}
	der := base64.decode(encoded)
	if der.len == 0 {
		return error('nethernet: PEM block is not valid base64')
	}
	return der
}
