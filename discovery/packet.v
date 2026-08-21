module discovery

// Packet is one of the three messages carried on the discovery port.
pub type Packet = MessagePacket | RequestPacket | ResponsePacket

pub const id_request_packet = u16(0)

pub const id_response_packet = u16(1)

pub const id_message_packet = u16(2)

// max_payload_length matches the u16 length prefix a packet carries.
const max_payload_length = 65535

// RequestPacket is what a client broadcasts to find games. It carries nothing:
// the question is the packet's existence.
pub struct RequestPacket {}

// ResponsePacket is a server's answer, describing its world.
pub struct ResponsePacket {
pub mut:
	// application_data is a ServerData in its binary form. It travels
	// hex-encoded, which is how the game writes it.
	application_data []u8
}

// MessagePacket carries one NetherNet signal between two networks.
pub struct MessagePacket {
pub mut:
	// recipient_id is the network the signal is for. It is not the connection
	// ID: a network ID outlives any one connection, and the connection ID is
	// inside the data.
	recipient_id u64
	// data is the signal in its wire form.
	data string
}

// Header prefixes every packet.
struct Header {
	packet_id u16
	sender_id u64
}

// header_padding is eight reserved bytes the game writes as zero and ignores on
// the way in.
const header_padding = 8

// marshal encodes a packet, encrypts it and prefixes the HMAC that
// authenticates it.
pub fn marshal(pk Packet, sender_id u64) []u8 {
	mut body := Writer{}
	body.u16(packet_id(pk))
	body.u64(sender_id)
	body.bytes([]u8{len: header_padding})
	write_packet(pk, mut body)

	// The length counts itself as well as the body, which is how the game
	// writes it.
	mut payload := Writer{}
	payload.u16(u16(body.data.len + 2))
	payload.bytes(body.data)

	mut out := checksum(payload.data)
	out << encrypt(payload.data)
	return out
}

// unmarshal decrypts and decodes a packet, returning it with the network ID of
// the sender.
pub fn unmarshal(data []u8) !(Packet, u64) {
	if data.len < checksum_size {
		return error('discovery: packet of ${data.len} bytes is shorter than its checksum')
	}
	payload := decrypt(data[checksum_size..])!

	// The HMAC is checked before anything in the payload is believed, so a
	// packet from something that does not hold the key is never parsed.
	if !hmac_equal(data[..checksum_size], checksum(payload)) {
		return error('discovery: packet checksum does not match')
	}

	mut r := Reader{
		data: payload
	}
	// The length prefix is redundant with the datagram's own length, and the
	// game does not check it either.
	r.u16()!
	id := r.u16()!
	sender_id := r.u64()!
	r.take(header_padding)!

	pk := read_packet(id, mut r)!
	if r.remaining() != 0 {
		return error('discovery: ${r.remaining()} bytes left after the packet')
	}
	return pk, sender_id
}

fn packet_id(pk Packet) u16 {
	return match pk {
		RequestPacket { id_request_packet }
		ResponsePacket { id_response_packet }
		MessagePacket { id_message_packet }
	}
}

fn write_packet(pk Packet, mut w Writer) {
	match pk {
		RequestPacket {}
		ResponsePacket {
			// The data is hex-encoded before it is length-prefixed, so the
			// length counts the text and not the bytes it stands for.
			encoded := pk.application_data.hex()
			w.u32(u32(encoded.len))
			w.bytes(encoded.bytes())
		}
		MessagePacket {
			w.u64(pk.recipient_id)
			w.u32(u32(pk.data.len))
			w.bytes(pk.data.bytes())
		}
	}
}

fn read_packet(id u16, mut r Reader) !Packet {
	match id {
		id_request_packet {
			return RequestPacket{}
		}
		id_response_packet {
			return ResponsePacket{
				application_data: decode_hex(read_prefixed(mut r)!.bytestr())!
			}
		}
		id_message_packet {
			return MessagePacket{
				recipient_id: r.u64()!
				data:         read_prefixed(mut r)!.bytestr()
			}
		}
		else {
			return error('discovery: unknown packet ID ${id}')
		}
	}
}

// read_prefixed reads a u32-length-prefixed byte string, refusing a length that
// could not fit in the packet.
fn read_prefixed(mut r Reader) ![]u8 {
	length := r.u32()!
	if length > u32(max_payload_length) {
		return error('discovery: length ${length} exceeds the ${max_payload_length}-byte maximum')
	}
	return r.take(int(length))!
}

fn decode_hex(text string) ![]u8 {
	if text.len % 2 != 0 {
		return error('discovery: hex string of ${text.len} characters has no whole number of bytes')
	}
	mut out := []u8{cap: text.len / 2}
	for i := 0; i < text.len; i += 2 {
		out << u8(hex_digit(text[i])! << 4 | hex_digit(text[i + 1])!)
	}
	return out
}

fn hex_digit(c u8) !u8 {
	return match true {
		c >= `0` && c <= `9` { c - `0` }
		c >= `a` && c <= `f` { c - `a` + 10 }
		c >= `A` && c <= `F` { c - `A` + 10 }
		else { error('discovery: "${c.ascii_str()}" is not a hex digit') }
	}
}

// hmac_equal compares two MACs in constant time, so a peer cannot learn the
// expected value one byte at a time.
fn hmac_equal(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut difference := u8(0)
	for i in 0 .. a.len {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}
